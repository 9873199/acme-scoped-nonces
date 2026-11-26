"""Nonce management tests for acme.client.ClientNetwork."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import logging
import threading
import time

import josepy as jose
import pytest
import requests
from requests.structures import CaseInsensitiveDict

from acme import errors
from acme import jws as acme_jws
from acme import messages
from acme._internal.tests import test_util
from acme.client import ClientNetwork
from acme.client import NonceManager

KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))

DIR_A_NONCE = 'https://ca-a.test/acme/new-nonce'
DIR_A_ORDER = 'https://ca-a.test/acme/new-order'
DIR_B_NONCE = 'https://ca-b.test/acme/new-nonce'
DIR_B_ORDER = 'https://ca-b.test/acme/new-order'


def b64(value: bytes) -> str:
    """Encode a nonce as an unpadded JOSE base64url header value."""
    return jose.b64encode(value).decode('ascii')


def response(url: str, status: int = 200, *,
             nonce: str | None = None,
             json_body: dict | None = None,
             content: bytes = b'',
             content_type: str | None = None) -> requests.Response:
    """Build a requests.Response without using the network."""
    result = requests.Response()
    result.status_code = status
    result.url = url
    result.headers = CaseInsensitiveDict()
    result.history = []
    result.request = requests.Request('POST', url).prepare()
    result.encoding = 'utf-8'
    if nonce is not None:
        result.headers['Replay-Nonce'] = nonce
    if json_body is not None:
        content = json.dumps(json_body).encode()
        content_type = content_type or 'application/json'
    if content_type is not None:
        result.headers['Content-Type'] = content_type
    result._content = content
    return result


def bad_nonce_response(url: str, nonce: str) -> requests.Response:
    """Build an ACME badNonce problem response that carries a fresh nonce."""
    return response(
        url, status=400, nonce=nonce,
        json_body=messages.Error.with_code('badNonce').to_json(),
        content_type='application/problem+json')


@dataclass
class RecordedPost:
    """A verified POST recorded by the fake HTTP session."""
    url: str
    payload: bytes
    nonce: bytes
    protected_url: str
    kid: str | None
    jws: acme_jws.JWS


class FakeSession:
    """Local requests.Session replacement that verifies every JWS."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[tuple[str, str, dict]] = []
        self.posts: list[RecordedPost] = []

    def mount(self, *_args, **_kwargs):
        pass

    def close(self):
        pass

    def request(self, method, url, *args, **kwargs):
        self.calls.append((method, url, kwargs))
        post = None
        if method == 'POST':
            parsed = acme_jws.JWS.json_loads(kwargs['data'])
            assert parsed.verify(KEY.public_key())
            combined = parsed.signature.combined
            post = RecordedPost(
                url=url,
                payload=parsed.payload,
                nonce=combined.nonce,
                protected_url=combined.url,
                kid=combined.kid,
                jws=parsed)
            self.posts.append(post)
        return self.handler(method, url, kwargs, post)

    def head_calls(self) -> list[tuple[str, dict]]:
        return [(url, kwargs) for method, url, kwargs in self.calls
                if method == 'HEAD']


def make_network(handler, *, manager: NonceManager | None = None,
                 account: str | None = 'https://ca-a.test/acct/1',
                 retries: int = 1):
    net = ClientNetwork(
        KEY, account={'uri': account} if account is not None else None,
        alg=jose.RS256, nonce_manager=manager,
        max_bad_nonce_retries=retries)
    session = FakeSession(handler)
    net.session = session
    return net, session


class MockJSON(jose.JSONDeSerializable):
    """Minimal serializable business object."""

    def __init__(self, value):
        self.value = value

    def to_partial_json(self):
        return {'value': self.value}

    @classmethod
    def from_json(cls, jobj):
        return cls(jobj['value'])


class SideEffectJSON(jose.JSONDeSerializable):
    """Object whose serialized body would change if serialized twice."""

    def __init__(self):
        self.serializations = 0

    def to_partial_json(self):
        return {'ignored': True}

    def json_dumps(self, *args, **kwargs):
        self.serializations += 1
        return json.dumps({'serialization': self.serializations})

    @classmethod
    def from_json(cls, jobj):
        return cls()


def test_nonces_are_isolated_by_directory():
    manager = NonceManager()

    def handler(method, url, _kwargs, _post):
        if method == 'HEAD':
            nonce = b64(b'a-head') if url == DIR_A_NONCE else b64(b'b-head')
            return response(url, nonce=nonce)
        nonce = b64(b'a-response') if url == DIR_A_ORDER else b64(b'b-response')
        return response(url, nonce=nonce)

    net_a, session_a = make_network(handler, manager=manager,
                                    account='https://ca-a.test/acct/1')
    net_b, session_b = make_network(handler, manager=manager,
                                    account='https://ca-b.test/acct/1')

    net_a.post(DIR_A_ORDER, MockJSON('a'), new_nonce_url=DIR_A_NONCE)
    net_b.post(DIR_B_ORDER, MockJSON('b'), new_nonce_url=DIR_B_NONCE)

    assert [post.nonce for post in session_a.posts] == [b'a-head']
    assert [post.nonce for post in session_b.posts] == [b'b-head']
    assert session_a.posts[0].protected_url == DIR_A_ORDER
    assert session_b.posts[0].protected_url == DIR_B_ORDER


def test_same_nonce_value_can_exist_in_two_directory_scopes():
    manager = NonceManager()

    def handler(_method, url, _kwargs, _post):
        if url in (DIR_A_NONCE, DIR_B_NONCE):
            return response(url, nonce=b64(b'shared'))
        if url == DIR_A_ORDER:
            return response(url, nonce=b64(b'a-response'))
        return response(url, nonce=b64(b'b-response'))

    net_a, session_a = make_network(handler, manager=manager,
                                    account='https://ca-a.test/acct/1')
    net_b, session_b = make_network(handler, manager=manager,
                                    account='https://ca-b.test/acct/1')

    net_a.post(DIR_A_ORDER, MockJSON('a'), new_nonce_url=DIR_A_NONCE)
    net_b.post(DIR_B_ORDER, MockJSON('b'), new_nonce_url=DIR_B_NONCE)

    assert [post.nonce for post in session_a.posts] == [b'shared']
    assert [post.nonce for post in session_b.posts] == [b'shared']


def test_account_scope_is_isolated_by_default():
    manager = NonceManager()
    heads = [b'a-head', b'b-head']

    def handler(method, url, _kwargs, _post):
        if method == 'HEAD':
            return response(url, nonce=b64(heads.pop(0)))
        if url == DIR_A_ORDER and _post.nonce == b'a-head':
            return response(url, nonce=b64(b'a-response'))
        return response(url, nonce=b64(b'b-response'))

    net_a, session_a = make_network(
        handler, manager=manager, account='https://ca-a.test/acct/a')
    net_b, session_b = make_network(
        handler, manager=manager, account='https://ca-a.test/acct/b')

    net_a.post(DIR_A_ORDER, MockJSON('a'), new_nonce_url=DIR_A_NONCE)
    net_b.post(DIR_A_ORDER, MockJSON('b'), new_nonce_url=DIR_A_NONCE)

    assert [post.nonce for post in session_a.posts] == [b'a-head']
    assert [post.nonce for post in session_b.posts] == [b'b-head']


def test_serialization_cannot_change_operation_account_scope():
    manager = NonceManager()
    head_nonces = [b'a-head', b'b-head']
    post_count = 0
    net_ref = {}

    class MutatingAccountJSON(MockJSON):
        def json_dumps(self, *args, **kwargs):
            net_ref['value'].account = {'uri': 'https://ca-a.test/acct/b'}
            return json.dumps({'value': self.value})

    def handler(method, url, _kwargs, _post):
        nonlocal post_count
        if method == 'HEAD':
            return response(url, nonce=b64(head_nonces.pop(0)))
        post_count += 1
        if post_count == 1:
            return bad_nonce_response(url, b64(b'from-error'))
        if post_count == 2:
            return response(url, nonce=b64(b'a-response'))
        return response(url, nonce=b64(b'b-response'))

    net, session = make_network(
        handler, manager=manager, account='https://ca-a.test/acct/a')
    net_ref['value'] = net

    net.post(
        DIR_A_ORDER, MutatingAccountJSON('body'),
        new_nonce_url=DIR_A_NONCE)
    net.post(
        DIR_A_ORDER, MockJSON('next'), new_nonce_url=DIR_A_NONCE)

    assert [post.nonce for post in session.posts] == [
        b'a-head', b'from-error', b'b-head']
    assert [post.kid for post in session.posts] == [
        'https://ca-a.test/acct/a',
        'https://ca-a.test/acct/a',
        'https://ca-a.test/acct/b',
    ]


def test_cross_account_sharing_is_explicit_and_uniform():
    manager = NonceManager(allow_cross_account=True)
    heads = [b'a-head']

    def handler(method, url, _kwargs, _post):
        if method == 'HEAD':
            return response(url, nonce=b64(heads.pop(0)))
        if _post.nonce == b'a-head':
            return response(url, nonce=b64(b'a-response'))
        return response(url, nonce=b64(b'b-response'))

    net_a, session_a = make_network(
        handler, manager=manager, account='https://ca-a.test/acct/a')
    net_b, session_b = make_network(
        handler, manager=manager, account='https://ca-a.test/acct/b')

    net_a.post(DIR_A_ORDER, MockJSON('a'), new_nonce_url=DIR_A_NONCE)
    net_b.post(DIR_A_ORDER, MockJSON('b'), new_nonce_url=DIR_A_NONCE)

    assert [post.nonce for post in session_a.posts] == [b'a-head']
    assert [post.nonce for post in session_b.posts] == [b'a-response']
    assert not session_b.head_calls()


def test_capacity_lifetime_and_duplicate_suppression():
    now = [100.0]
    manager = NonceManager(max_size=2, max_age=10, clock=lambda: now[0])
    scope = manager.scope_for('https://ca-a.test/acme/new-nonce')

    assert manager.add_nonce(scope, b64(b'one'))
    assert not manager.add_nonce(scope, b64(b'one'))
    assert manager.add_nonce(scope, b64(b'two'))
    assert manager.add_nonce(scope, b64(b'three'))

    assert manager.available_count(scope) == 2
    assert manager.claim_nonce(scope) == b'two'
    assert manager.claim_nonce(scope) == b'three'
    assert manager.claim_nonce(scope) is None

    now[0] += 11
    assert manager.available_count(scope) == 0


def test_concurrent_claim_hands_out_a_value_exactly_once():
    manager = NonceManager()
    scope = manager.scope_for('https://ca-a.test/acme/new-nonce')
    manager.add_nonce(scope, b64(b'only'))
    barrier = threading.Barrier(8)

    def claim():
        barrier.wait()
        return manager.claim_nonce(scope)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: claim(), range(8)))

    assert results.count(b'only') == 1
    assert results.count(None) == 7


def test_cancelled_leader_does_not_cancel_other_waiters():
    first_started = threading.Event()
    release_first = threading.Event()
    head_count = 0
    lock = threading.Lock()

    def handler(method, url, _kwargs, _post):
        nonlocal head_count
        if method == 'HEAD':
            with lock:
                head_count += 1
                this_call = head_count
            if this_call == 1:
                first_started.set()
                assert release_first.wait(5)
                raise asyncio.CancelledError()
            return response(url, nonce=b64(b'fresh'))
        return response(url, nonce=b64(b'after'))

    net, session = make_network(handler, manager=NonceManager())

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            net.post, DIR_A_ORDER, MockJSON('first'), None,
            **{'new_nonce_url': DIR_A_NONCE})
        assert first_started.wait(5)
        second = executor.submit(
            net.post, DIR_A_ORDER, MockJSON('second'), None,
            **{'new_nonce_url': DIR_A_NONCE})
        time.sleep(0.1)
        release_first.set()

        with pytest.raises(asyncio.CancelledError):
            first.result(timeout=5)
        assert second.result(timeout=5).ok

    assert head_count == 2
    assert [post.nonce for post in session.posts] == [b'fresh']


def test_bad_nonce_uses_error_nonce_and_serializes_body_once():
    manager = NonceManager()
    post_count = 0
    scope = {}

    def handler(method, url, _kwargs, post):
        nonlocal post_count
        if method == 'HEAD':
            return response(url, nonce=b64(b'initial'))
        post_count += 1
        if post_count == 1:
            manager.add_nonce(scope['value'], b64(b'pool-nonce'))
            manager.add_nonce(scope['value'], b64(b'from-error'))
            return bad_nonce_response(url, b64(b'from-error'))
        assert post.nonce == b'from-error'
        return response(url, nonce=b64(b'after'))

    net, session = make_network(handler, manager=manager, retries=2)
    scope['value'] = net._nonce_scope(DIR_A_ORDER, DIR_A_NONCE)
    obj = SideEffectJSON()

    assert net.post(
        DIR_A_ORDER, obj, new_nonce_url=DIR_A_NONCE).ok

    assert obj.serializations == 1
    assert [post.nonce for post in session.posts] == [
        b'initial', b'from-error']
    assert session.posts[0].payload == session.posts[1].payload
    assert session.posts[0].payload == b'{"serialization": 1}'
    assert manager.claim_nonce(scope['value']) == b'pool-nonce'


def test_consecutive_bad_nonce_is_bounded():
    post_count = 0
    nonces = [b'one', b'two', b'three', b'four']

    def handler(method, url, _kwargs, _post):
        nonlocal post_count
        if method == 'HEAD':
            return response(url, nonce=b64(b'initial'))
        post_count += 1
        return bad_nonce_response(url, b64(nonces[post_count - 1]))

    net, session = make_network(handler, retries=2)

    with pytest.raises(messages.Error):
        net.post(DIR_A_ORDER, MockJSON('body'), new_nonce_url=DIR_A_NONCE)

    assert post_count == 3
    assert [post.nonce for post in session.posts] == [
        b'initial', b'one', b'two']


def test_post_as_get_keeps_empty_signed_payload():
    def handler(method, url, _kwargs, _post):
        if method == 'HEAD':
            return response(url, nonce=b64(b'initial'))
        return response(url, nonce=b64(b'next'))

    net, session = make_network(handler)
    assert net.post(
        DIR_A_ORDER, None, new_nonce_url=DIR_A_NONCE).ok
    assert session.posts[0].payload == b''
    assert session.posts[0].nonce == b'initial'


def test_connection_errors_are_not_retried():
    post_count = 0

    def handler(method, url, _kwargs, _post):
        nonlocal post_count
        if method == 'HEAD':
            return response(url, nonce=b64(b'initial'))
        post_count += 1
        raise requests.exceptions.ConnectionError('connection failed')

    net, _session = make_network(handler, retries=3)

    with pytest.raises(requests.exceptions.ConnectionError):
        net.post(DIR_A_ORDER, MockJSON('body'), new_nonce_url=DIR_A_NONCE)

    assert post_count == 1


def test_redirected_nonce_endpoint_does_not_populate_pool():
    post_count = 0
    manager = NonceManager()

    def handler(method, url, _kwargs, _post):
        nonlocal post_count
        if method == 'HEAD':
            return response(url, status=302, nonce=b64(b'redirected'),
                            content_type='text/plain')
        post_count += 1
        return response(url, nonce=b64(b'unused'))

    net, session = make_network(handler, manager=manager)
    scope = net._nonce_scope(DIR_A_ORDER, DIR_A_NONCE)

    with pytest.raises(errors.ClientError):
        net.post(DIR_A_ORDER, MockJSON('body'), new_nonce_url=DIR_A_NONCE)

    assert post_count == 0
    assert manager.available_count(scope) == 0
    assert session.head_calls()[0][1]['allow_redirects'] is False


def test_error_page_nonce_does_not_populate_pool():
    post_count = 0
    manager = NonceManager()

    def handler(method, url, _kwargs, _post):
        nonlocal post_count
        if method == 'HEAD':
            return response(url, nonce=b64(b'initial'))
        post_count += 1
        return response(url, status=500, nonce=b64(b'error-page'),
                        content=b'<html>error</html>',
                        content_type='text/html')

    net, _session = make_network(
        handler, manager=manager, retries=3)
    scope = net._nonce_scope(DIR_A_ORDER, DIR_A_NONCE)

    with pytest.raises(errors.ClientError):
        net.post(DIR_A_ORDER, MockJSON('body'), new_nonce_url=DIR_A_NONCE)

    assert post_count == 1
    assert manager.available_count(scope) == 0


def test_logs_do_not_include_jws_or_nonces(caplog):
    def handler(method, url, _kwargs, _post):
        if method == 'HEAD':
            return response(url, nonce=b64(b'secret-head'))
        return response(url, nonce=b64(b'secret-response'))

    net, _session = make_network(handler)

    with caplog.at_level(logging.DEBUG, logger='acme.client'):
        assert net.post(
            DIR_A_ORDER, MockJSON('body'), new_nonce_url=DIR_A_NONCE).ok

    assert b64(b'secret-head') not in caplog.text
    assert b64(b'secret-response') not in caplog.text
    assert '"protected"' not in caplog.text
    assert '"signatures"' not in caplog.text
    assert 'PRIVATE KEY' not in caplog.text
