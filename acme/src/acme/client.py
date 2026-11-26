"""ACME client API."""
import asyncio
import base64
from collections import deque
from concurrent.futures import CancelledError as FutureCancelledError
import datetime
from email.utils import parsedate_tz
import http.client as http_client
import logging
import math
import random
import re
import threading
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import Mapping
from typing import Optional
from typing import Union
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from cryptography import x509

import josepy as jose
import requests
from requests.adapters import HTTPAdapter
from requests.utils import parse_header_links

from acme import challenges
from acme import crypto_util
from acme import errors
from acme import jws
from acme import messages

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_TIMEOUT = 45
DEFAULT_NONCE_POOL_SIZE = 32
DEFAULT_NONCE_MAX_AGE = 5 * 60
DEFAULT_BAD_NONCE_RETRIES = 1

_NONCE_RE = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')
_CANCELLATION_ERRORS = (asyncio.CancelledError, FutureCancelledError, GeneratorExit)
_UNSET = object()


def _canonical_url(url: str) -> str:
    """Return a stable URL representation for nonce scope keys."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or '/'
    return urlunsplit((scheme, netloc, path, parts.query, ''))


def _decode_nonce(value: Union[str, bytes]) -> bytes:
    """Decode an RFC 8555 Replay-Nonce using JOSE base64url rules."""
    if isinstance(value, bytes):
        try:
            value = value.decode('ascii')
        except UnicodeDecodeError as error:
            raise jose.DeserializationError('Nonce is not ASCII') from error
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise jose.DeserializationError('Nonce is not valid JOSE base64url')
    try:
        return jws.Header._fields['nonce'].decode(value)
    except jose.DeserializationError:
        raise
    except (TypeError, ValueError) as error:
        raise jose.DeserializationError('Nonce is not valid JOSE base64url') from error


class _NonceFetch:
    """One single-flight nonce fetch shared by concurrent pool waiters."""
    __slots__ = ('done', 'cancelled', 'error')

    def __init__(self) -> None:
        self.done = False
        self.cancelled = False
        self.error: Optional[BaseException] = None


class _NoncePool:
    """State for one directory/account nonce scope."""
    __slots__ = ('available', 'seen', 'pending')

    def __init__(self) -> None:
        self.available: deque[tuple[float, bytes]] = deque()
        self.seen: dict[bytes, float] = {}
        self.pending: Optional[_NonceFetch] = None


class NonceManager:
    """Thread-safe ACME nonce pool with directory and account isolation.

    A nonce is scoped to the exact newNonce URL that supplied it. By default,
    nonces are also scoped to the account identity, so a manager may safely be
    shared by clients for different CAs and by clients using different accounts
    on the same CA. Set ``allow_cross_account=True`` to explicitly share nonces
    between accounts using the same directory; this policy is applied uniformly
    to every directory.

    Each scope has a bounded number of nonces and every nonce expires after
    ``max_age`` seconds. Claiming a nonce removes it atomically, so a single
    available value cannot be handed to two concurrent requests.
    """

    def __init__(self, max_size: int = DEFAULT_NONCE_POOL_SIZE,
                 max_age: float = DEFAULT_NONCE_MAX_AGE, *,
                 allow_cross_account: bool = False,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if max_size < 1:
            raise ValueError('max_size must be positive')
        if max_age <= 0:
            raise ValueError('max_age must be positive')
        self.max_size = max_size
        self.max_age = max_age
        self.allow_cross_account = allow_cross_account
        self._clock = clock
        self._condition = threading.Condition()
        self._pools: dict[tuple[str, Optional[str]], _NoncePool] = {}

    def scope_for(self, directory_url: str,
                  account_id: Optional[str] = None) -> tuple[str, Optional[str]]:
        """Build the nonce scope for a directory and account."""
        account_scope = None if self.allow_cross_account else account_id
        return (_canonical_url(directory_url), account_scope)

    def _pool_locked(self, scope: tuple[str, Optional[str]]) -> _NoncePool:
        pool = self._pools.get(scope)
        if pool is None:
            pool = _NoncePool()
            self._pools[scope] = pool
        return pool

    def _prune_locked(self, pool: _NoncePool, now: float) -> None:
        while pool.available and pool.available[0][0] <= now:
            pool.available.popleft()
        for nonce, expires in list(pool.seen.items()):
            if expires <= now:
                del pool.seen[nonce]

    def _claim_locked(self, pool: _NoncePool) -> Optional[bytes]:
        now = self._clock()
        self._prune_locked(pool, now)
        if not pool.available:
            return None
        _, nonce = pool.available.popleft()
        return nonce

    def _add_locked(self, pool: _NoncePool, nonce: bytes) -> bool:
        now = self._clock()
        self._prune_locked(pool, now)
        if nonce in pool.seen:
            return False
        while len(pool.available) >= self.max_size:
            pool.available.popleft()
        expires = now + self.max_age
        pool.available.append((expires, nonce))
        pool.seen[nonce] = expires
        return True

    def add_nonce(self, scope: tuple[str, Optional[str]],
                  nonce: Union[str, bytes]) -> bool:
        """Add a nonce to a scope, rejecting duplicate values."""
        decoded = _decode_nonce(nonce)
        with self._condition:
            return self._add_locked(self._pool_locked(scope), decoded)

    def mark_used(self, scope: tuple[str, Optional[str]],
                  nonce: Union[str, bytes]) -> None:
        """Remember a consumed nonce so a duplicate response cannot revive it."""
        decoded = _decode_nonce(nonce)
        with self._condition:
            pool = self._pool_locked(scope)
            now = self._clock()
            self._prune_locked(pool, now)
            pool.available = deque(
                entry for entry in pool.available if entry[1] != decoded)
            pool.seen.setdefault(decoded, now + self.max_age)

    def claim_nonce(self, scope: tuple[str, Optional[str]]) -> Optional[bytes]:
        """Atomically claim one available nonce from a scope."""
        with self._condition:
            return self._claim_locked(self._pool_locked(scope))

    def get_nonce(self, scope: tuple[str, Optional[str]],
                  fetch: Callable[[], Union[str, bytes]]) -> bytes:
        """Claim a nonce, coalescing concurrent fetches when the pool is empty.

        If the thread performing a fetch is cancelled, another waiter takes
        over instead of inheriting that cancellation. Other fetch failures are
        propagated to all current waiters.
        """
        duplicate_fetches = 0
        while True:
            with self._condition:
                pool = self._pool_locked(scope)
                nonce = self._claim_locked(pool)
                if nonce is not None:
                    return nonce
                if duplicate_fetches >= 3:
                    raise errors.NonceError(
                        'Server repeatedly returned a nonce that was already used')
                pending = pool.pending
                if pending is None:
                    pending = _NonceFetch()
                    pool.pending = pending
                    leader = True
                else:
                    leader = False

            if leader:
                try:
                    fetched = _decode_nonce(fetch())
                except BaseException as error:
                    cancelled = isinstance(error, _CANCELLATION_ERRORS)
                    with self._condition:
                        if pool.pending is pending:
                            pool.pending = None
                        pending.done = True
                        pending.cancelled = cancelled
                        if not cancelled:
                            pending.error = error
                        self._condition.notify_all()
                    raise
                with self._condition:
                    added = self._add_locked(pool, fetched)
                    if pool.pending is pending:
                        pool.pending = None
                    pending.done = True
                    self._condition.notify_all()
                duplicate_fetches = 0 if added else duplicate_fetches + 1
            else:
                with self._condition:
                    while not pending.done:
                        self._condition.wait()
                    if pending.error is not None:
                        raise pending.error
                    if pending.cancelled:
                        continue

    def available_count(self, scope: tuple[str, Optional[str]]) -> int:
        """Return the number of currently usable nonces in a scope."""
        with self._condition:
            pool = self._pool_locked(scope)
            self._prune_locked(pool, self._clock())
            return len(pool.available)


class ClientV2:
    """ACME client for a v2 API.

    :ivar messages.Directory directory:
    :ivar .ClientNetwork net: Client network.
    """

    def __init__(self, directory: messages.Directory, net: 'ClientNetwork') -> None:
        """Initialize.

        :param .messages.Directory directory: Directory Resource
        :param .ClientNetwork net: Client network.
        """
        self.directory = directory
        self.net = net

    def new_account(self, new_account: messages.NewRegistration) -> messages.RegistrationResource:
        """Register.

        :param .NewRegistration new_account:

        :raises .ConflictError: in case the account already exists

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`
        """
        response = self._post(self.directory['newAccount'], new_account)
        # if account already exists
        if response.status_code == 200 and 'Location' in response.headers:
            raise errors.ConflictError(response.headers['Location'])
        # "Instance of 'Field' has no key/contact member" bug:
        regr = self._regr_from_response(response)
        self.net.account = regr
        return regr

    def query_registration(self, regr: messages.RegistrationResource
                           ) -> messages.RegistrationResource:
        """Query server about registration.

        :param messages.RegistrationResource regr: Existing Registration
            Resource.

        """
        self.net.account = self._get_v2_account(regr, True)

        return self.net.account

    def update_registration(self, regr: messages.RegistrationResource,
                            update: Optional[messages.Registration] = None
                            ) -> messages.RegistrationResource:
        """Update registration.

        :param messages.RegistrationResource regr: Registration Resource.
        :param messages.Registration update: Updated body of the
            resource. If not provided, body will be taken from `regr`.

        :returns: Updated Registration Resource.
        :rtype: `.RegistrationResource`

        """
        # https://github.com/certbot/certbot/issues/6155
        regr = self._get_v2_account(regr)

        update = regr.body if update is None else update
        body = messages.UpdateRegistration(**dict(update))
        updated_regr = self._send_recv_regr(regr, body=body)
        self.net.account = updated_regr
        return updated_regr

    def _get_v2_account(self, regr: messages.RegistrationResource, update_body: bool = False
                       ) -> messages.RegistrationResource:
        self.net.account = None
        only_existing_reg = regr.body.update(only_return_existing=True)
        response = self._post(self.directory['newAccount'], only_existing_reg)
        updated_uri = response.headers['Location']
        new_regr = regr.update(body=messages.Registration.from_json(response.json())
                               if update_body else regr.body,
                               uri=updated_uri)
        self.net.account = new_regr
        return new_regr

    def new_order(self, csr_pem: bytes, profile: Optional[str] = None) -> messages.OrderResource:
        """Request a new Order object from the server.

        :param bytes csr_pem: A CSR in PEM format.

        :returns: The newly created order.
        :rtype: OrderResource
        """
        csr = x509.load_pem_x509_csr(csr_pem)
        dns_names, ip_addrs  = crypto_util.get_identifiers_from_x509(csr.subject, csr.extensions)
        identifiers = []
        for name in dns_names:
            identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_FQDN,
                value=name))
        for ip in ip_addrs:
            identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_IP,
                value=str(ip)))
        if profile is None:
            profile = ""
        order = messages.NewOrder(identifiers=identifiers, profile=profile)
        response = self._post(self.directory['newOrder'], order)
        body = messages.Order.from_json(response.json())
        authorizations = []
        # pylint has trouble understanding our josepy based objects which use
        # things like custom metaclass logic. body.authorizations should be a
        # list of strings containing URLs so let's disable this check here.
        for url in body.authorizations:  # pylint: disable=not-an-iterable
            authorizations.append(self._authzr_from_response(self._post_as_get(url), uri=url))
        return messages.OrderResource(
            body=body,
            uri=response.headers.get('Location'),
            authorizations=authorizations,
            csr_pem=csr_pem)

    def poll(self, authzr: messages.AuthorizationResource
             ) -> tuple[messages.AuthorizationResource, requests.Response]:
        """Poll Authorization Resource for status.

        :param authzr: Authorization Resource
        :type authzr: `.AuthorizationResource`

        :returns: Updated Authorization Resource and HTTP response.

        :rtype: (`.AuthorizationResource`, `requests.Response`)

        """
        response = self._post_as_get(authzr.uri)
        updated_authzr = self._authzr_from_response(
            response, authzr.body.identifier, authzr.uri)
        return updated_authzr, response

    def poll_and_finalize(self, orderr: messages.OrderResource,
                          deadline: Optional[datetime.datetime] = None) -> messages.OrderResource:
        """Poll authorizations and finalize the order.

        If no deadline is provided, this method will timeout after 90
        seconds.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout

        :returns: finalized order
        :rtype: messages.OrderResource

        """
        if deadline is None:
            deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
        orderr = self.poll_authorizations(orderr, deadline)
        return self.finalize_order(orderr, deadline)

    def poll_authorizations(self, orderr: messages.OrderResource, deadline: datetime.datetime
                            ) -> messages.OrderResource:
        """Poll Order Resource for status."""
        responses = []
        for url in orderr.body.authorizations:
            while datetime.datetime.now() < deadline:
                authzr = self._authzr_from_response(self._post_as_get(url), uri=url)
                if authzr.body.status != messages.STATUS_PENDING:  # pylint: disable=no-member
                    responses.append(authzr)
                    break
                time.sleep(1)
        # If we didn't get a response for every authorization, we fell through
        # the bottom of the loop due to hitting the deadline.
        if len(responses) < len(orderr.body.authorizations):
            raise errors.TimeoutError()
        failed = []
        for authzr in responses:
            if authzr.body.status != messages.STATUS_VALID:
                for chall in authzr.body.challenges:
                    if chall.error is not None:
                        failed.append(authzr)
        if failed:
            raise errors.ValidationError(failed)
        return orderr.update(authorizations=responses)

    def begin_finalization(self, orderr: messages.OrderResource
                           ) -> messages.OrderResource:
        """Start the process of finalizing an order.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout

        :returns: updated order
        :rtype: messages.OrderResource

        :raises .messages.Error: If server indicates order is not yet in ready state,
            it will return a 403 (Forbidden) error with a problem document/error code of type
            "orderNotReady"

        """
        csr = x509.load_pem_x509_csr(orderr.csr_pem)
        wrapped_csr = messages.CertificateRequest(csr=csr)
        res = self._post(orderr.body.finalize, wrapped_csr)
        orderr = orderr.update(body=messages.Order.from_json(res.json()))
        return orderr

    def poll_finalization(self, orderr: messages.OrderResource,
                          deadline: datetime.datetime,
                          fetch_alternative_chains: bool = False
                          ) -> messages.OrderResource:
        """
        Poll an order that has been finalized for its status.
        If it becomes valid, obtain the certificate.

        If a finalization request previously returned `orderNotReady`,
        poll until ready, send a new finalization request, and continue
        polling until valid as above.

        :returns: finalized order (with certificate)
        :rtype: messages.OrderResource
        """
        sleep_seconds: float = 1
        while datetime.datetime.now() < deadline:
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
            response = self._post_as_get(orderr.uri)
            body = messages.Order.from_json(response.json())
            if body.status == messages.STATUS_INVALID:
                # "invalid": The certificate will not be issued.  Consider this
                # order process abandoned.
                if body.error is not None:
                    raise errors.IssuanceError(body.error)
                raise errors.Error(
                    "The certificate order failed. No further information was provided "
                    "by the server.")
            elif body.status == messages.STATUS_READY:
                # "ready": The server agrees that the requirements have been
                # fulfilled, and is awaiting finalization.  Submit a finalization
                # request.
                self.begin_finalization(orderr)
                sleep_seconds = 1
            elif body.status == messages.STATUS_VALID and body.certificate is not None:
                # "valid": The server has issued the certificate and provisioned its
                # URL to the "certificate" field of the order.  Download the
                # certificate.
                certificate_response = self._post_as_get(body.certificate)
                orderr = orderr.update(body=body, fullchain_pem=certificate_response.text)
                if fetch_alternative_chains:
                    alt_chains_urls = self._get_links(certificate_response, 'alternate')
                    alt_chains = [self._post_as_get(url).text for url in alt_chains_urls]
                    orderr = orderr.update(alternative_fullchains_pem=alt_chains)
                return orderr
            elif body.status == messages.STATUS_PROCESSING:
                # "processing": The certificate is being issued.  Send a POST-as-GET request after
                # the time given in the Retry-After header field of the response, if any.
                retry_after = self.retry_after(response, 1)
                # Whatever Retry-After the ACME server requests, the polling must not take
                # longer than the overall deadline
                retry_after = min(retry_after, deadline)
                sleep_seconds = (retry_after - datetime.datetime.now()).total_seconds()
        raise errors.TimeoutError()

    def finalize_order(self, orderr: messages.OrderResource, deadline: datetime.datetime,
                       fetch_alternative_chains: bool = False) -> messages.OrderResource:
        """Finalize an order and obtain a certificate.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout
        :param bool fetch_alternative_chains: whether to also fetch alternative
            certificate chains

        :returns: finalized order
        :rtype: messages.OrderResource

        """
        try:
            self.begin_finalization(orderr)
        except messages.Error as e:
            if e.code != 'orderNotReady':
                raise e
        return self.poll_finalization(orderr, deadline, fetch_alternative_chains)

    def renewal_time(self, cert_pem: bytes
        ) -> tuple[Optional[datetime.datetime], datetime.datetime]:
        """Return an appropriate time to attempt renewal of the certificate,
        and the next time to ask the ACME server for renewal info.

        If the certificate has already expired, renewal info isn't checked.
        Instead, the certificate's notAfter time is returned and the certificate
        should be immediately renewed.

        If the ACME directory has a "renewalInfo" field, the response will be
        based on a fetch of the renewal info resource for the certificate
        (https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html).

        If there is no "renewalInfo" field, this function will return a tuple of
        None, and the next time to ask the ACME server for renewal info.

        This function may make other network calls in the future (e.g., OCSP
        or CRL).

        :param bytes cert_pem: cert as pem file

        :returns: Tuple of time to attempt renewal, next time to ask for renewal info

        :raises errors.ARIError: If an error occurs fetching ARI from the
            server or the returned suggested renewal window is invalid
            (its end time is not after its start time). Fetch errors use
            explicit exception chaining so the original error can be
            accessed through the __cause__ attribute if desired.

        """
        now = datetime.datetime.now()
        # https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html#section-4.3.3
        default_retry_after = datetime.timedelta(seconds=6 * 60 * 60)

        cert = x509.load_pem_x509_certificate(cert_pem)

        # from https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html#section-4.3, "Clients
        # MUST NOT check a certificate's RenewalInfo after the certificate has expired."
        #
        # we call datetime.datetime.now here with the UTC argument to create a timezone aware
        # datetime object that can be compared with the UTC notAfter from cryptography
        if cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
            return cert.not_valid_after_utc, now + default_retry_after

        try:
            renewal_info_base_url = self.directory['renewalInfo']
        except KeyError:
            return None, now + default_retry_after

        ari_url = renewal_info_base_url + '/' + _renewal_info_path_component(cert)
        try:
            resp = self.net.get(ari_url, content_type='application/json')
        except Exception as e:  # pylint: disable=broad-except
            error_msg = f'failed to fetch renewal_info URL {ari_url}'
            raise errors.ARIError(error_msg, now + default_retry_after) from e
        renewal_info: messages.RenewalInfo = messages.RenewalInfo.from_json(resp.json())

        start = renewal_info.suggested_window.start # pylint: disable=no-member
        end = renewal_info.suggested_window.end # pylint: disable=no-member

        if end <= start:
            raise errors.ARIError('suggestedWindow end must be after start',
                                  now + default_retry_after)

        delta_seconds = (end - start).total_seconds()
        random_seconds = random.uniform(0, delta_seconds)
        random_time = start + datetime.timedelta(seconds=random_seconds)

        retry_after = self.retry_after(resp, default_retry_after.seconds)
        return random_time, retry_after


    def revoke(self, cert: x509.Certificate, rsn: int) -> None:
        """Revoke certificate.

        :param x509.Certificate cert: `x509.Certificate`

        :param int rsn: Reason code for certificate revocation.

        :raises .ClientError: If revocation is unsuccessful.

        """
        self._revoke(cert, rsn, self.directory['revokeCert'])

    def external_account_required(self) -> bool:
        """Checks if ACME server requires External Account Binding authentication."""
        return hasattr(self.directory, 'meta') and \
               hasattr(self.directory.meta, 'external_account_required') and \
               self.directory.meta.external_account_required

    def _post_as_get(self, *args: Any, **kwargs: Any) -> requests.Response:
        """
        Send GET request using the POST-as-GET protocol.
        :param args:
        :param kwargs:
        :return:
        """
        new_args = args[:1] + (None,) + args[1:]
        return self._post(*new_args, **kwargs)

    def _get_links(self, response: requests.Response, relation_type: str) -> list[str]:
        """
        Retrieves all Link URIs of relation_type from the response.
        :param requests.Response response: The requests HTTP response.
        :param str relation_type: The relation type to filter by.
        """
        # Can't use response.links directly because it drops multiple links
        # of the same relation type, which is possible in RFC8555 responses.
        if 'Link' not in response.headers:
            return []
        links = parse_header_links(response.headers['Link'])
        return [link['url'] for link in links
                if 'rel' in link and 'url' in link and link['rel'] == relation_type]

    @classmethod
    def get_directory(cls, url: str, net: 'ClientNetwork') -> messages.Directory:
        """
        Retrieves the ACME directory (RFC 8555 section 7.1.1) from the ACME server.
        :param str url: the URL where the ACME directory is available
        :param ClientNetwork net: the ClientNetwork to use to make the request

        :returns: the ACME directory object
        :rtype: messages.Directory
        """
        return messages.Directory.from_json(net.get(url).json())

    @classmethod
    def _regr_from_response(cls, response: requests.Response, uri: Optional[str] = None,
                            terms_of_service: Optional[str] = None
                            ) -> messages.RegistrationResource:
        if 'terms-of-service' in response.links:
            terms_of_service = response.links['terms-of-service']['url']

        return messages.RegistrationResource(
            body=messages.Registration.from_json(response.json()),
            uri=response.headers.get('Location', uri),
            terms_of_service=terms_of_service)

    def _send_recv_regr(self, regr: messages.RegistrationResource,
                        body: messages.Registration) -> messages.RegistrationResource:
        response = self._post(regr.uri, body)

        # TODO: Boulder returns httplib.ACCEPTED
        #assert response.status_code == httplib.OK

        # TODO: Boulder does not set Location or Link on update
        # (c.f. acme-spec #94)

        return self._regr_from_response(
            response, uri=regr.uri,
            terms_of_service=regr.terms_of_service)

    def _post(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Wrapper around self.net.post that adds the newNonce URL.

        This is used to retry the request in case of a badNonce error.

        """
        kwargs.setdefault('new_nonce_url', getattr(self.directory, 'newNonce'))
        return self.net.post(*args, **kwargs)

    def deactivate_registration(self, regr: messages.RegistrationResource
                                ) -> messages.RegistrationResource:
        """Deactivate registration.

        :param messages.RegistrationResource regr: The Registration Resource
            to be deactivated.

        :returns: The Registration resource that was deactivated.
        :rtype: `.RegistrationResource`

        """
        return self.update_registration(regr, messages.Registration.from_json(
            {"status": "deactivated", "contact": None}))

    def deactivate_authorization(self,
                                 authzr: messages.AuthorizationResource
                                 ) -> messages.AuthorizationResource:
        """Deactivate authorization.

        :param messages.AuthorizationResource authzr: The Authorization resource
            to be deactivated.

        :returns: The Authorization resource that was deactivated.
        :rtype: `.AuthorizationResource`

        """
        body = messages.UpdateAuthorization(status='deactivated')
        response = self._post(authzr.uri, body)
        return self._authzr_from_response(response,
            authzr.body.identifier, authzr.uri)

    def _authzr_from_response(self, response: requests.Response,
                              identifier: Optional[messages.Identifier] = None,
                              uri: Optional[str] = None) -> messages.AuthorizationResource:
        authzr = messages.AuthorizationResource(
            body=messages.Authorization.from_json(response.json()),
            uri=response.headers.get('Location', uri))
        if identifier is not None and authzr.body.identifier != identifier:  # pylint: disable=no-member
            raise errors.UnexpectedUpdate(authzr)
        return authzr

    def answer_challenge(self, challb: messages.ChallengeBody,
                         response: challenges.ChallengeResponse) -> messages.ChallengeResource:
        """Answer challenge.

        :param challb: Challenge Resource body.
        :type challb: `.ChallengeBody`

        :param response: Corresponding Challenge response
        :type response: `.challenges.ChallengeResponse`

        :returns: Challenge Resource with updated body.
        :rtype: `.ChallengeResource`

        :raises .UnexpectedUpdate:

        """
        resp = self._post(challb.uri, response)
        try:
            authzr_uri = resp.links['up']['url']
        except KeyError:
            raise errors.ClientError('"up" Link header missing')
        challr = messages.ChallengeResource(
            authzr_uri=authzr_uri,
            body=messages.ChallengeBody.from_json(resp.json()))
        # TODO: check that challr.uri == resp.headers['Location']?
        if challr.uri != challb.uri:
            raise errors.UnexpectedUpdate(challr.uri)
        return challr

    @classmethod
    def retry_after(cls, response: requests.Response, default: int) -> datetime.datetime:
        """Compute next `poll` time based on response ``Retry-After`` header.

        Handles integers and various datestring formats per
        https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.37

        :param requests.Response response: Response from `poll`.
        :param int default: Default value (in seconds), used when
            ``Retry-After`` header is not present or invalid.

        :returns: Time point when next `poll` should be performed.
        :rtype: `datetime.datetime`

        """
        retry_after = response.headers.get('Retry-After', str(default))
        try:
            seconds = int(retry_after)
        except ValueError:
            # The RFC 2822 parser handles all of RFC 2616's cases in modern
            # environments (primarily HTTP 1.1+ but also py27+)
            when = parsedate_tz(retry_after)
            if when is not None:
                try:
                    tz_secs = datetime.timedelta(when[-1] if when[-1] is not None else 0)
                    return datetime.datetime(*when[:7]) - tz_secs
                except (ValueError, OverflowError):
                    pass
            seconds = default

        return datetime.datetime.now() + datetime.timedelta(seconds=seconds)

    def _revoke(self, cert: x509.Certificate, rsn: int, url: str) -> None:
        """Revoke certificate.

        :param .x509.Certificate cert: `x509.Certificate`

        :param int rsn: Reason code for certificate revocation.

        :param str url: ACME URL to post to

        :raises .ClientError: If revocation is unsuccessful.

        """
        response = self._post(url,
                              messages.Revocation(
                                certificate=cert,
                                reason=rsn))
        if response.status_code != http_client.OK:
            raise errors.ClientError(
                'Successful revocation must return HTTP OK status')


class ClientNetwork:
    """Wrapper around requests that signs POSTs for authentication.

    Also adds user agent, and handles Content-Type. Nonces are held in a
    :class:`NonceManager`, which may be shared between ClientNetwork instances.
    """
    JSON_CONTENT_TYPE = 'application/json'
    JOSE_CONTENT_TYPE = 'application/jose+json'
    JSON_ERROR_CONTENT_TYPE = 'application/problem+json'
    REPLAY_NONCE_HEADER = 'Replay-Nonce'

    """Initialize.

    :param josepy.JWK key: Account private key. Required to use .post().
    :param messages.RegistrationResource account: Account object. Required if you are
            planning to use .post() for anything other than creating a new account;
            may be set later after registering.
    :param josepy.JWASignature alg: Algorithm to use in signing JWS.
    :param bool verify_ssl: Whether to verify certificates on SSL connections.
    :param str user_agent: String to send as User-Agent header.
    :param int timeout: Timeout for requests.
    :param NonceManager nonce_manager: Nonce manager to use. If omitted, a
        private manager is created for this ClientNetwork.
    :param int nonce_pool_size: Maximum nonces kept per directory/account when
        creating a private nonce manager.
    :param float nonce_max_age: Maximum nonce age in seconds when creating a
        private nonce manager.
    :param bool allow_cross_account: Explicitly allow nonce sharing between
        accounts using the same directory. This only applies when creating a
        private nonce manager.
    :param int max_bad_nonce_retries: Maximum number of badNonce re-signs.
    """
    def __init__(self, key: Optional[jose.JWK] = None,
                 account: Optional[messages.RegistrationResource] = None,
                 alg: jose.JWASignature = jose.RS256, verify_ssl: bool = True,
                 user_agent: str = 'acme-python', timeout: int = DEFAULT_NETWORK_TIMEOUT,
                 nonce_manager: Optional[NonceManager] = None,
                 nonce_pool_size: int = DEFAULT_NONCE_POOL_SIZE,
                 nonce_max_age: float = DEFAULT_NONCE_MAX_AGE,
                 allow_cross_account: bool = False,
                 max_bad_nonce_retries: int = DEFAULT_BAD_NONCE_RETRIES) -> None:
        if max_bad_nonce_retries < 0:
            raise ValueError('max_bad_nonce_retries must not be negative')
        self.key = key
        self.account = account
        self.alg = alg
        self.verify_ssl = verify_ssl
        self.nonce_manager = nonce_manager or NonceManager(
            max_size=nonce_pool_size, max_age=nonce_max_age,
            allow_cross_account=allow_cross_account)
        self._nonce_manager = self.nonce_manager
        self.max_bad_nonce_retries = max_bad_nonce_retries
        self._jws_payload_context = threading.local()
        self.user_agent = user_agent
        self.session = requests.Session()
        self._default_timeout = timeout
        adapter = HTTPAdapter()

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def __del__(self) -> None:
        # Try to close the session, but don't show exceptions to the
        # user if the call to close() fails. See #4840.
        try:
            self.session.close()
        except Exception:  # pylint: disable=broad-except
            pass

    def _serialize_payload(self, obj: Optional[jose.JSONDeSerializable]) -> bytes:
        """Serialize a business object exactly once for a POST operation."""
        if obj is None:
            return b''
        return obj.json_dumps(indent=2).encode()

    def _sign_payload(self, payload: bytes, nonce: bytes, url: str,
                      kid: Any = _UNSET, key: Any = _UNSET,
                      alg: Any = _UNSET) -> str:
        """Sign an already serialized payload in an ACME JWS."""
        logger.debug('Signing JWS with a %d byte payload', len(payload))
        signing_key = self.key if key is _UNSET else key
        signing_alg = self.alg if alg is _UNSET else alg
        assert signing_key
        kwargs = {
            "alg": signing_alg,
            "nonce": nonce,
            "url": url,
            "key": signing_key
        }
        # newAccount and revokeCert work without the kid
        # newAccount must not have kid
        if kid is _UNSET:
            kid = self._account_uri()
        if kid is not None:
            kwargs["kid"] = kid
        return jws.JWS.sign(payload, **cast(Mapping[str, Any], kwargs)).json_dumps(indent=2)

    def _wrap_in_jws(self, obj: Optional[jose.JSONDeSerializable],
                     nonce: bytes, url: str, *,
                     payload: Optional[bytes] = None) -> str:
        """Wrap `JSONDeSerializable` object in JWS.

        .. todo:: Implement ``acmePath``.

        :param josepy.JSONDeSerializable obj:
        :param str url: The URL to which this object will be POSTed
        :param str nonce:
        :param bytes payload: Already serialized payload. If omitted, ``obj``
            is serialized exactly once here.
        :rtype: str

        """
        if payload is None:
            payload = getattr(self._jws_payload_context, 'value', None)
        if payload is None:
            payload = self._serialize_payload(obj)
        kid = getattr(self._jws_payload_context, 'kid', _UNSET)
        key = getattr(self._jws_payload_context, 'key', _UNSET)
        alg = getattr(self._jws_payload_context, 'alg', _UNSET)
        return self._sign_payload(
            payload, nonce, url, kid=kid, key=key, alg=alg)

    @classmethod
    def _check_response(cls, response: requests.Response,
                        content_type: Optional[str] = None) -> requests.Response:
        """Check response content and its type.

        .. note::
           Checking is not strict: wrong server response ``Content-Type``
           HTTP header is ignored if response is an expected JSON object
           (c.f. Boulder #56).

        :param str content_type: Expected Content-Type response header.
            If JSON is expected and not present in server response, this
            function will raise an error. Otherwise, wrong Content-Type
            is ignored, but logged.

        :raises .messages.Error: If server response body
            carries HTTP Problem (https://datatracker.ietf.org/doc/html/rfc7807).
        :raises .ClientError: In case of other networking errors.

        """
        response_ct = response.headers.get('Content-Type')
        # Strip parameters from the media-type (rfc2616#section-3.7)
        if response_ct:
            response_ct = response_ct.split(';')[0].strip()
        try:
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            jobj = response.json()
        except ValueError:
            jobj = None

        if 300 <= response.status_code < 400:
            raise errors.ClientError(
                f'Unexpected redirect response (HTTP {response.status_code})')

        if response.status_code == 409:
            raise errors.ConflictError(response.headers.get('Location', 'UNKNOWN-LOCATION'))

        if not response.ok:
            if jobj is not None:
                if response_ct != cls.JSON_ERROR_CONTENT_TYPE:
                    logger.debug(
                        'Ignoring wrong Content-Type (%r) for JSON Error',
                        response_ct)
                try:
                    error = messages.Error.from_json(jobj)
                except jose.DeserializationError as error:
                    # Couldn't deserialize JSON object
                    raise errors.ClientError((response, error))
                error.response = response
                raise error
            else:
                # response is not JSON object
                raise errors.ClientError(response)
        else:
            if jobj is not None and response_ct != cls.JSON_CONTENT_TYPE:
                logger.debug(
                    'Ignoring wrong Content-Type (%r) for JSON decodable '
                    'response', response_ct)

            if content_type == cls.JSON_CONTENT_TYPE and jobj is None:
                raise errors.ClientError(f'Unexpected response Content-Type: {response_ct}')

        return response

    def _send_request(self, method: str, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        """Send HTTP request.

        Makes sure that `verify_ssl` is respected. Logs request and
        response (with headers). For allowed parameters please see
        `requests.request`.

        :param str method: method for the new `requests.Request` object
        :param str url: URL for the new `requests.Request` object

        :raises requests.exceptions.RequestException: in case of any problems

        :returns: HTTP Response
        :rtype: `requests.Response`


        """
        logger.debug('Sending %s request to %s (request body omitted).', method, url)
        kwargs['verify'] = self.verify_ssl
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('User-Agent', self.user_agent)
        kwargs.setdefault('timeout', self._default_timeout)
        response = self.session.request(method, url, *args, **kwargs)

        # If an Accept header was sent in the request, the response may not be
        # UTF-8 encoded. In this case, we don't set response.encoding and log
        # the base64 response instead of raw bytes to keep binary data out of the logs.
        debug_content: Union[bytes, str]
        if method == "POST":
            response.encoding = "utf-8"
            debug_content = "<response body omitted>"
        elif "Accept" in kwargs["headers"]:
            debug_content = base64.b64encode(response.content)
        else:
            # We set response.encoding so response.text knows the response is
            # UTF-8 encoded instead of trying to guess the encoding that was
            # used which is error prone. This setting affects all future
            # accesses of .text made on the returned response object as well.
            response.encoding = "utf-8"
            debug_content = response.text
        raw_nonce = response.headers.get(self.REPLAY_NONCE_HEADER)
        nonce_header = raw_nonce if isinstance(raw_nonce, str) and raw_nonce else None
        if nonce_header and isinstance(debug_content, str):
            debug_content = debug_content.replace(nonce_header, '<redacted>')
        elif nonce_header:
            encoded_nonce = nonce_header.encode('ascii')
            debug_content = debug_content.replace(encoded_nonce, b'<redacted>')
        safe_headers = "\n".join(
            "{0}: {1}".format(
                k, '<redacted>' if 'nonce' in k.lower()
                else (str(v).replace(nonce_header, '<redacted>')
                      if nonce_header else v))
            for k, v in response.headers.items())
        logger.debug('Received response:\nHTTP %d\n%s\n\n%s',
                     response.status_code,
                     safe_headers,
                     debug_content)
        return response

    def head(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Send HEAD request without checking the response.

        Note, that `_check_response` is not called, as it is expected
        that status code other than successfully 2xx will be returned, or
        messages2.Error will be raised by the server.

        """
        return self._send_request('HEAD', *args, **kwargs)

    def get(self, url: str, content_type: str = JSON_CONTENT_TYPE,
            **kwargs: Any) -> requests.Response:
        """Send GET request and check response."""
        return self._check_response(
            self._send_request('GET', url, **kwargs), content_type=content_type)

    def _account_uri(self) -> Optional[str]:
        """Return the current account URI, if one is configured."""
        if self.account is not None:
            try:
                return self.account["uri"]
            except (KeyError, TypeError, AttributeError):
                return None
        return None

    def _account_snapshot(self) -> tuple[Optional[str], str]:
        """Snapshot the account URI and non-secret scope identity."""
        account = self.account
        if account is not None:
            try:
                account_uri = account["uri"]
            except (KeyError, TypeError, AttributeError):
                account_uri = None
            if account_uri is not None:
                return account_uri, f'account:{account_uri}'
            return None, f'account-object:{id(account)}'
        key = self.key
        if key is not None:
            try:
                return None, 'key:' + jose.b64encode(key.thumbprint()).decode('ascii')
            except Exception:  # pylint: disable=broad-except
                return None, f'key-object:{id(key)}'
        return None, 'anonymous'

    def _account_identity(self) -> str:
        """Return a non-secret identity for the current account configuration."""
        return self._account_snapshot()[1]

    def _nonce_scope(self, request_url: str, new_nonce_url: Optional[str],
                     account_identity: Any = _UNSET
                     ) -> tuple[str, Optional[str]]:
        if new_nonce_url is not None:
            directory_url = new_nonce_url
        else:
            parts = urlsplit(request_url)
            directory_url = (
                urlunsplit((parts.scheme, parts.netloc, '/', '', ''))
                if parts.scheme or parts.netloc else request_url)
        if account_identity is _UNSET:
            account_identity = self._account_identity()
        return self.nonce_manager.scope_for(
            directory_url, account_identity)

    @staticmethod
    def _is_direct_response(response: requests.Response,
                            expected_url: Optional[str]) -> bool:
        status = getattr(response, 'status_code', None)
        if isinstance(status, int) and 300 <= status < 400:
            return False
        history = getattr(response, 'history', None)
        if isinstance(history, (list, tuple)) and history:
            return False
        response_url = getattr(response, 'url', None)
        if (expected_url is not None and isinstance(response_url, str)
                and response_url
                and _canonical_url(response_url) != _canonical_url(expected_url)):
            return False
        return True

    @classmethod
    def _response_nonce(cls, response: requests.Response) -> str:
        nonce = response.headers.get(cls.REPLAY_NONCE_HEADER)
        if nonce is None:
            raise errors.MissingNonce(response)
        try:
            _decode_nonce(nonce)
        except jose.DeserializationError as error:
            raise errors.BadNonce(nonce, error)
        return nonce

    def _add_nonce(self, response: requests.Response,
                   scope: tuple[str, Optional[str]],
                   expected_url: Optional[str] = None) -> None:
        if not self._is_direct_response(response, expected_url):
            raise errors.ClientError('Refusing nonce from a redirected response')
        nonce = self._response_nonce(response)
        self.nonce_manager.add_nonce(scope, nonce)
        logger.debug('Stored a replay nonce for the configured directory scope')

    def _retry_nonce(self, response: Optional[requests.Response],
                     url: str, scope: tuple[str, Optional[str]]) -> Optional[bytes]:
        if response is None or not self._is_direct_response(response, url):
            return None
        nonce = response.headers.get(self.REPLAY_NONCE_HEADER)
        if nonce is None:
            return None
        try:
            _decode_nonce(nonce)
        except jose.DeserializationError:
            logger.debug('Ignoring invalid nonce in badNonce response')
            return None
        self.nonce_manager.mark_used(scope, nonce)
        return _decode_nonce(nonce)

    def _get_nonce(self, url: str, new_nonce_url: Optional[str],
                   scope: Optional[tuple[str, Optional[str]]] = None) -> bytes:
        if scope is None:
            scope = self._nonce_scope(url, new_nonce_url)

        def fetch_nonce() -> bytes:
            logger.debug('Requesting a fresh nonce for the configured directory scope')
            if new_nonce_url is None:
                response = self.head(url)
                if (not response.ok
                        and response.status_code != http_client.METHOD_NOT_ALLOWED):
                    raise errors.ClientError(
                        'Refusing nonce from an unsuccessful response')
            else:
                response = self._check_response(
                    self.head(new_nonce_url, allow_redirects=False),
                    content_type=None)
            if not self._is_direct_response(response, new_nonce_url or url):
                raise errors.ClientError('Refusing nonce from a redirected response')
            return self._response_nonce(response)

        return self.nonce_manager.get_nonce(scope, fetch_nonce)

    def post(self, url: str, obj: Optional[jose.JSONDeSerializable],
             content_type: str = JOSE_CONTENT_TYPE, **kwargs: Any) -> requests.Response:
        """POST an object wrapped in `.JWS` and check the response.

        The payload is serialized once before the first request. A badNonce
        response may cause a bounded re-sign using the nonce supplied by that
        response; the payload is never re-serialized and connection errors are
        never retried.
        """
        new_nonce_url = kwargs.pop('new_nonce_url', None)
        key = self.key
        alg = self.alg
        if not key:
            raise errors.Error("acme.ClientNetwork with no private key can't POST.")

        kid, account_identity = self._account_snapshot()
        scope = self._nonce_scope(url, new_nonce_url, account_identity)
        payload = self._serialize_payload(obj)
        retry_nonce: Optional[bytes] = None

        for attempt in range(self.max_bad_nonce_retries + 1):
            nonce = retry_nonce
            retry_nonce = None
            if nonce is None:
                nonce = self._get_nonce(url, new_nonce_url, scope)

            try:
                return self._post_once(
                    url, obj, content_type, _payload=payload, _nonce=nonce,
                    _scope=scope, _kid=kid, _key=key, _alg=alg,
                    new_nonce_url=new_nonce_url, **kwargs)
            except messages.Error as error:
                if error.code != 'badNonce' or attempt >= self.max_bad_nonce_retries:
                    raise
                error_response = getattr(error, 'response', None)
                if (error_response is not None
                        and not self._is_direct_response(error_response, url)):
                    raise
                retry_nonce = self._retry_nonce(error_response, url, scope)
                logger.debug('Retrying after badNonce (retry %d of %d)',
                             attempt + 1, self.max_bad_nonce_retries)

        raise AssertionError('unreachable')  # pragma: no cover

    def _post_once(self, url: str, obj: Optional[jose.JSONDeSerializable],
                   content_type: str = JOSE_CONTENT_TYPE, **kwargs: Any
                   ) -> requests.Response:
        new_nonce_url = kwargs.pop('new_nonce_url', None)
        payload = kwargs.pop('_payload', None)
        nonce = kwargs.pop('_nonce', None)
        scope = kwargs.pop('_scope', None)
        kid = kwargs.pop('_kid', _UNSET)
        key = kwargs.pop('_key', _UNSET)
        alg = kwargs.pop('_alg', _UNSET)
        if key is _UNSET:
            key = self.key
        if alg is _UNSET:
            alg = self.alg
        if not key:
            raise errors.Error("acme.ClientNetwork with no private key can't POST.")
        if payload is None:
            payload = self._serialize_payload(obj)
        if nonce is None:
            nonce = self._get_nonce(url, new_nonce_url, scope)
        if scope is None:
            scope = self._nonce_scope(url, new_nonce_url)
        if kid is _UNSET:
            kid = self._account_snapshot()[0]

        previous_payload = getattr(self._jws_payload_context, 'value', None)
        previous_kid = getattr(self._jws_payload_context, 'kid', _UNSET)
        previous_key = getattr(self._jws_payload_context, 'key', _UNSET)
        previous_alg = getattr(self._jws_payload_context, 'alg', _UNSET)
        self._jws_payload_context.value = payload
        self._jws_payload_context.kid = kid
        self._jws_payload_context.key = key
        self._jws_payload_context.alg = alg
        try:
            data = self._wrap_in_jws(obj, nonce, url)
        finally:
            if previous_payload is None:
                del self._jws_payload_context.value
            else:
                self._jws_payload_context.value = previous_payload
            if previous_kid is _UNSET:
                del self._jws_payload_context.kid
            else:
                self._jws_payload_context.kid = previous_kid
            if previous_key is _UNSET:
                del self._jws_payload_context.key
            else:
                self._jws_payload_context.key = previous_key
            if previous_alg is _UNSET:
                del self._jws_payload_context.alg
            else:
                self._jws_payload_context.alg = previous_alg
        headers = dict(kwargs.pop('headers', {}) or {})
        if content_type is not None:
            headers.setdefault('Content-Type', content_type)
        kwargs['headers'] = headers
        kwargs['allow_redirects'] = False
        response = self._send_request('POST', url, data=data, **kwargs)
        response = self._check_response(response, content_type=content_type)
        self._add_nonce(response, scope, expected_url=url)
        return response

def _renewal_info_path_component(cert: x509.Certificate) -> str:
    akid_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    key_identifier = akid_ext.value.key_identifier # type: ignore[attr-defined]

    akid_encoded = base64.urlsafe_b64encode(key_identifier).decode('ascii').replace("=", "")

    # We add one to the reported bit_length so there is room for the sign bit.
    # https://docs.python.org/3/library/stdtypes.html#int.bit_length
    # "Return the number of bits necessary to represent an integer in binary, excluding
    # the sign and leading zeros"
    serial = cert.serial_number
    encoded_serial_len = math.ceil((serial.bit_length()+1)/8)
    # Serials are encoded as ASN.1 INTEGERS, which means big endian and signed (two's complement).
    # https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#integer-encoding
    serial_bytes = serial.to_bytes(encoded_serial_len, byteorder='big', signed=True)
    serial_encoded = base64.urlsafe_b64encode(serial_bytes).decode('ascii').replace("=", "")

    return f"{akid_encoded}.{serial_encoded}"
