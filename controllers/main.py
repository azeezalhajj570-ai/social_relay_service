# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import requests
from werkzeug.urls import url_encode, url_join
from werkzeug.wrappers import Response

from odoo import http
from odoo.exceptions import UserError
from odoo.http import request

_logger = logging.getLogger(__name__)

_MEDIA_ERROR_TOKEN = {
    'facebook': 'facebook_missing_configuration',
    'instagram': 'missing_parameters',
    'youtube': 'youtube_missing_configuration',
    'twitter': 'wrong_configuration',
    'linkedin': 'missing_parameters',
}

_MEDIA_TEMPLATE_KEY = {
    'facebook': 'social_relay_service.facebook_add_accounts_url',
    'instagram': 'social_relay_service.instagram_add_accounts_url',
    'youtube': 'social_relay_service.youtube_add_accounts_url',
    'twitter': 'social_relay_service.twitter_add_accounts_url',
    'linkedin': 'social_relay_service.linkedin_add_accounts_url',
}


class SocialRelayServiceController(http.Controller):
    _TWITTER_ENDPOINT = 'https://api.twitter.com'
    _LINKEDIN_SCOPE = (
        'r_basicprofile r_organization_followers w_member_social w_member_social_feed '
        'rw_organization_admin w_organization_social w_organization_social_feed '
        'r_organization_social r_organization_social_feed'
    )

    def _icp(self):
        return request.env['ir.config_parameter'].sudo()

    def _media(self, media_type):
        return request.env['social.media'].sudo().search([('media_type', '=', media_type)], limit=1)

    def _oauth_error(self, media, status=400):
        token = _MEDIA_ERROR_TOKEN[media]
        return Response(token, mimetype='text/plain', status=status)

    def _redirect_from_action(self, media, action):
        url = (action or {}).get('url')
        if not url:
            return self._oauth_error(media)
        return request.redirect(url, local=False)

    @staticmethod
    def _is_truthy(value):
        return str(value).strip().lower() in ('1', 'true', 'yes', 'on')

    def _resolve_base_url(self, returning_url=None):
        configured_base_url = (self._icp().get_param('web.base.url') or '').strip()
        request_base_url = request.httprequest.url_root.rstrip('/')
        base_url = configured_base_url.rstrip('/') or request_base_url

        # Keep relay redirects aligned with the callback scheme/host when behind reverse proxies.
        if returning_url:
            callback = urlparse(returning_url)
            base = urlparse(base_url)
            if callback.scheme in ('http', 'https') and callback.netloc and callback.netloc == base.netloc and callback.scheme != base.scheme:
                base_url = f'{callback.scheme}://{callback.netloc}'

        return base_url

    @staticmethod
    def _is_absolute_http_url(url):
        parsed = urlparse((url or '').strip())
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)

    @staticmethod
    def _append_query_params(url, params):
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.update({key: '' if value is None else str(value) for key, value in (params or {}).items()})
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _twitter_oauth_signature(self, method, url, params, consumer_secret, oauth_token_secret=''):
        # OAuth 1.0 requires RFC3986 encoding for both the normalized parameters and signing key.
        signing_key = '&'.join([
            quote(str(consumer_secret or ''), safe='-._~'),
            quote(str(oauth_token_secret or ''), safe='-._~'),
        ])
        query = '&'.join([
            '%s=%s' % (
                quote(str(key), safe='-._~'),
                quote(str(params[key]), safe='-._~'),
            )
            for key in sorted(params.keys())
        ])
        base_string = '&'.join([
            str(method or '').upper(),
            quote(url, safe='-._~'),
            quote(query, safe='-._~'),
        ])
        digest = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
        return base64.b64encode(digest).decode()

    def _twitter_oauth_header(self, oauth_callback):
        consumer_key = (
            self._icp().get_param('social.twitter_consumer_key')
            or self._icp().get_param('social_relay_service.twitter_consumer_key')
        )
        consumer_secret = (
            self._icp().get_param('social.twitter_consumer_secret_key')
            or self._icp().get_param('social_relay_service.twitter_consumer_secret')
        )
        if not consumer_key or not consumer_secret:
            return None

        request_token_url = url_join(self._TWITTER_ENDPOINT, "oauth/request_token")
        oauth_params = {
            'oauth_nonce': str(uuid.uuid4()),
            'oauth_consumer_key': consumer_key,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_version': '1.0',
            'oauth_callback': oauth_callback,
        }
        oauth_params['oauth_signature'] = self._twitter_oauth_signature(
            'POST',
            request_token_url,
            oauth_params,
            consumer_secret,
        )
        header = 'OAuth ' + ', '.join([
            '%s="%s"' % (key, quote(str(oauth_params[key]), safe='-._~'))
            for key in sorted(oauth_params.keys())
        ])
        return {'Authorization': header}

    def _render_add_accounts_url(self, media, returning_url, db_uuid):
        if not returning_url or not db_uuid:
            _logger.warning(
                'social_relay_service: missing add-account inputs media=%s returning_url=%s db_uuid=%s',
                media,
                bool(returning_url),
                bool(db_uuid),
            )
            return _MEDIA_ERROR_TOKEN[media]

        template = self._icp().get_param(_MEDIA_TEMPLATE_KEY[media])
        if not template:
            _logger.warning('social_relay_service: empty template media=%s key=%s', media, _MEDIA_TEMPLATE_KEY[media])
            return _MEDIA_ERROR_TOKEN[media]

        try:
            base_url = self._resolve_base_url(returning_url=returning_url)
            result = template.format(returning_url=returning_url, db_uuid=db_uuid, base_url=base_url)
            callback = urlparse(returning_url or '')
            rendered = urlparse(result or '')
            # Protect against templates hardcoded with http:// when callback is https://.
            if (
                callback.scheme == 'https'
                and rendered.scheme == 'http'
                and callback.netloc
                and rendered.netloc == callback.netloc
            ):
                result = result.replace('http://', 'https://', 1)
            _logger.info(
                'social_relay_service: add-account media=%s db_uuid=%s base_url=%s result=%s',
                media,
                db_uuid,
                base_url,
                result,
            )
            return result
        except Exception:
            _logger.exception('Invalid URL template for media %s', media)
            return _MEDIA_ERROR_TOKEN[media]

    @http.route('/api/social/facebook/1/add_accounts', type='http', auth='public', methods=['GET'], csrf=False)
    def add_facebook_accounts(self, returning_url=None, db_uuid=None, **kwargs):
        return Response(self._render_add_accounts_url('facebook', returning_url, db_uuid), mimetype='text/plain')

    @http.route('/api/social/instagram/1/add_accounts', type='http', auth='public', methods=['GET'], csrf=False)
    def add_instagram_accounts(self, returning_url=None, db_uuid=None, **kwargs):
        return Response(self._render_add_accounts_url('instagram', returning_url, db_uuid), mimetype='text/plain')

    @http.route('/api/social/youtube/1/add_accounts', type='http', auth='public', methods=['GET'], csrf=False)
    def add_youtube_accounts(self, returning_url=None, db_uuid=None, **kwargs):
        return Response(self._render_add_accounts_url('youtube', returning_url, db_uuid), mimetype='text/plain')

    @http.route('/api/social/twitter/1/add_accounts', type='http', auth='public', methods=['GET'], csrf=False)
    def add_twitter_accounts(self, returning_url=None, db_uuid=None, **kwargs):
        return Response(self._render_add_accounts_url('twitter', returning_url, db_uuid), mimetype='text/plain')

    @http.route('/api/social/linkedin/1/add_accounts', type='http', auth='public', methods=['GET'], csrf=False)
    def add_linkedin_accounts(self, returning_url=None, db_uuid=None, **kwargs):
        return Response(self._render_add_accounts_url('linkedin', returning_url, db_uuid), mimetype='text/plain')

    @http.route('/oauth/facebook', type='http', auth='user', methods=['GET'], csrf=False)
    def oauth_facebook(self, returning_url=None, db_uuid=None, **kwargs):
        facebook_app_id = self._icp().get_param('social.facebook_app_id')
        facebook_client_secret = self._icp().get_param('social.facebook_client_secret')
        media = self._media('facebook')
        if not media or not facebook_app_id or not facebook_client_secret:
            return self._oauth_error('facebook')
        action = media._add_facebook_accounts_from_configuration(facebook_app_id)
        return self._redirect_from_action('facebook', action)

    @http.route('/oauth/instagram', type='http', auth='user', methods=['GET'], csrf=False)
    def oauth_instagram(self, returning_url=None, db_uuid=None, **kwargs):
        instagram_app_id = self._icp().get_param('social.instagram_app_id')
        instagram_client_secret = self._icp().get_param('social.instagram_client_secret')
        media = self._media('instagram')
        if not media or not instagram_app_id or not instagram_client_secret:
            return self._oauth_error('instagram')
        action = media._add_instagram_accounts_from_configuration(instagram_app_id)
        return self._redirect_from_action('instagram', action)

    @http.route('/oauth/youtube', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_youtube(self, returning_url=None, db_uuid=None, **kwargs):
        youtube_client_id = (
            self._icp().get_param('social.youtube_oauth_client_id')
            or self._icp().get_param('social_relay_service.youtube_client_id')
        )
        youtube_client_secret = (
            self._icp().get_param('social.youtube_oauth_client_secret')
            or self._icp().get_param('social_relay_service.youtube_client_secret')
        )
        if not youtube_client_id or not youtube_client_secret:
            return self._oauth_error('youtube')

        if self._is_absolute_http_url(returning_url):
            relay_host = urlparse(self._resolve_base_url()).netloc
            callback_host = urlparse(returning_url).netloc
            if callback_host and relay_host and callback_host != relay_host:
                redirect_uri = url_join(self._resolve_base_url(), 'oauth/youtube/callback')
                state = json.dumps({'returning_url': returning_url})
                auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?%s' % url_encode({
                    'client_id': youtube_client_id,
                    'redirect_uri': redirect_uri,
                    'response_type': 'code',
                    'scope': ' '.join([
                        'https://www.googleapis.com/auth/youtube.force-ssl',
                        'https://www.googleapis.com/auth/youtube.upload',
                    ]),
                    'access_type': 'offline',
                    'prompt': 'consent',
                    'state': state,
                })
                return request.redirect(auth_url, local=False)

        media = self._media('youtube')
        if not media:
            return self._oauth_error('youtube')
        action = media._add_youtube_accounts_from_configuration(youtube_client_id)
        return self._redirect_from_action('youtube', action)

    @http.route('/oauth/youtube/callback', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_youtube_callback(self, code=None, state=None, error=None, error_description=None, **kwargs):
        youtube_client_id = (
            self._icp().get_param('social.youtube_oauth_client_id')
            or self._icp().get_param('social_relay_service.youtube_client_id')
        )
        youtube_client_secret = (
            self._icp().get_param('social.youtube_oauth_client_secret')
            or self._icp().get_param('social_relay_service.youtube_client_secret')
        )
        if not youtube_client_id or not youtube_client_secret:
            return self._oauth_error('youtube')

        try:
            state_data = json.loads(state or '{}')
        except json.JSONDecodeError:
            state_data = {}
        returning_url = state_data.get('returning_url')
        if not self._is_absolute_http_url(returning_url):
            return self._oauth_error('youtube')

        if error:
            return request.redirect(self._append_query_params(returning_url, {
                'error': error,
                'error_description': error_description or '',
            }), local=False)

        if not code:
            return request.redirect(self._append_query_params(returning_url, {
                'error': 'missing_authorization_code',
            }), local=False)

        redirect_uri = url_join(self._resolve_base_url(), 'oauth/youtube/callback')
        try:
            token_exchange_response = requests.post(
                'https://oauth2.googleapis.com/token',
                data={
                    'client_id': youtube_client_id,
                    'client_secret': youtube_client_secret,
                    'code': code,
                    'grant_type': 'authorization_code',
                    'access_type': 'offline',
                    'prompt': 'consent',
                    'redirect_uri': redirect_uri,
                },
                timeout=10,
            ).json()
        except requests.RequestException:
            _logger.exception('social_relay_service: youtube token exchange failed')
            return request.redirect(self._append_query_params(returning_url, {
                'error': 'upstream_error',
            }), local=False)

        if token_exchange_response.get('error'):
            return request.redirect(self._append_query_params(returning_url, {
                'error': token_exchange_response.get('error'),
                'error_description': token_exchange_response.get('error_description') or '',
            }), local=False)

        access_token = token_exchange_response.get('access_token')
        refresh_token = token_exchange_response.get('refresh_token')
        expires_in = token_exchange_response.get('expires_in', 0)
        if not access_token or not refresh_token:
            return request.redirect(self._append_query_params(returning_url, {
                'error': 'missing_token',
            }), local=False)

        return request.redirect(self._append_query_params(returning_url, {
            'iap_access_token': access_token,
            'iap_refresh_token': refresh_token,
            'iap_expires_in': expires_in,
        }), local=False)

    @http.route('/oauth/twitter', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_twitter(self, returning_url=None, db_uuid=None, **kwargs):
        consumer_key = (
            self._icp().get_param('social.twitter_consumer_key')
            or self._icp().get_param('social_relay_service.twitter_consumer_key')
        )
        consumer_secret = (
            self._icp().get_param('social.twitter_consumer_secret_key')
            or self._icp().get_param('social_relay_service.twitter_consumer_secret')
        )
        if not consumer_key or not consumer_secret:
            return self._oauth_error('twitter')

        if self._is_absolute_http_url(returning_url):
            relay_host = urlparse(self._resolve_base_url()).netloc
            callback_host = urlparse(returning_url).netloc
            if callback_host and relay_host and callback_host != relay_host:
                # Keep callback URL static for providers that validate it strictly.
                callback_url = url_join(self._resolve_base_url(), 'oauth/twitter/callback')
                request.session['social_relay_twitter_returning_url'] = returning_url
                twitter_oauth_url = url_join(self._TWITTER_ENDPOINT, "oauth/request_token")
                headers = self._twitter_oauth_header(callback_url)
                if not headers:
                    _logger.warning('social_relay_service: twitter consumer key/secret missing')
                    return self._oauth_error('twitter')
                response = requests.post(twitter_oauth_url, headers=headers, timeout=10)
                if response.status_code != 200:
                    _logger.warning(
                        'social_relay_service: twitter request_token failed status=%s body=%s',
                        response.status_code,
                        response.text,
                    )
                    return self._oauth_error('twitter')

                response_values = {
                    item.split('=')[0]: item.split('=')[1]
                    for item in response.text.split('&')
                    if '=' in item
                }
                oauth_token = response_values.get('oauth_token')
                if not oauth_token:
                    _logger.warning('social_relay_service: twitter request_token missing oauth_token body=%s', response.text)
                    return self._oauth_error('twitter')

                twitter_authorize_url = url_join(self._TWITTER_ENDPOINT, 'oauth/authorize')
                return request.redirect(f'{twitter_authorize_url}?oauth_token={oauth_token}', local=False)

        media = self._media('twitter')
        if not media:
            return self._oauth_error('twitter')
        try:
            action = media._add_twitter_accounts_from_configuration()
        except UserError:
            _logger.exception('social_relay_service: twitter oauth generation failed')
            return self._oauth_error('twitter')
        return self._redirect_from_action('twitter', action)

    @http.route('/oauth/twitter/callback', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_twitter_callback(self, returning_url=None, oauth_token=None, oauth_verifier=None, denied=None, **kwargs):
        returning_url = returning_url or request.session.pop('social_relay_twitter_returning_url', None)
        if not self._is_absolute_http_url(returning_url):
            return self._oauth_error('twitter')

        if denied:
            return request.redirect(self._append_query_params(returning_url, {'denied': denied}), local=False)

        if not oauth_token or not oauth_verifier:
            return request.redirect(self._append_query_params(returning_url, {'error': 'missing_oauth_tokens'}), local=False)

        return request.redirect(self._append_query_params(returning_url, {
            'oauth_token': oauth_token,
            'oauth_verifier': oauth_verifier,
            'iap_twitter_consumer_key': (
                self._icp().get_param('social.twitter_consumer_key')
                or self._icp().get_param('social_relay_service.twitter_consumer_key')
                or ''
            ),
        }), local=False)

    @http.route('/oauth/linkedin', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_linkedin(self, returning_url=None, db_uuid=None, **kwargs):
        linkedin_use_own_account = self._icp().get_param('social.linkedin_use_own_account')
        linkedin_app_id = self._icp().get_param('social.linkedin_app_id')
        linkedin_client_secret = self._icp().get_param('social.linkedin_client_secret')
        if not self._is_truthy(linkedin_use_own_account) or not linkedin_app_id or not linkedin_client_secret:
            return self._oauth_error('linkedin')

        if self._is_absolute_http_url(returning_url):
            relay_host = urlparse(self._resolve_base_url()).netloc
            callback_host = urlparse(returning_url).netloc
            if callback_host and relay_host and callback_host != relay_host:
                returning_query = dict(parse_qsl(urlparse(returning_url).query, keep_blank_values=True))
                consumer_state = returning_query.get('state', '')
                redirect_uri = url_join(self._resolve_base_url(), 'oauth/linkedin/callback')
                state = json.dumps({
                    'returning_url': returning_url,
                    'consumer_state': consumer_state,
                })
                linkedin_auth_url = 'https://www.linkedin.com/oauth/v2/authorization?%s' % url_encode({
                    'response_type': 'code',
                    'client_id': linkedin_app_id,
                    'redirect_uri': redirect_uri,
                    'state': state,
                    'scope': self._LINKEDIN_SCOPE,
                })
                return request.redirect(linkedin_auth_url, local=False)

        media = self._media('linkedin')
        if not media:
            return self._oauth_error('linkedin')
        action = media._add_linkedin_accounts_from_configuration(linkedin_app_id)
        return self._redirect_from_action('linkedin', action)

    @http.route('/oauth/linkedin/callback', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_linkedin_callback(self, code=None, state=None, error=None, error_description=None, **kwargs):
        linkedin_app_id = self._icp().get_param('social.linkedin_app_id')
        linkedin_client_secret = self._icp().get_param('social.linkedin_client_secret')
        if not linkedin_app_id or not linkedin_client_secret:
            return self._oauth_error('linkedin')

        try:
            state_data = json.loads(state or '{}')
        except json.JSONDecodeError:
            state_data = {}
        returning_url = state_data.get('returning_url')
        consumer_state = state_data.get('consumer_state', '')
        if not self._is_absolute_http_url(returning_url):
            return self._oauth_error('linkedin')

        if error:
            return request.redirect(self._append_query_params(returning_url, {
                'error': error,
                'error_description': error_description or '',
            }), local=False)
        if not code:
            return request.redirect(self._append_query_params(returning_url, {
                'error': 'missing_authorization_code',
            }), local=False)

        redirect_uri = url_join(self._resolve_base_url(), 'oauth/linkedin/callback')
        try:
            token_response = requests.post(
                'https://www.linkedin.com/oauth/v2/accessToken',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'client_id': linkedin_app_id,
                    'client_secret': linkedin_client_secret,
                },
                timeout=10,
            ).json()
        except requests.RequestException:
            _logger.exception('social_relay_service: linkedin token exchange failed')
            return request.redirect(self._append_query_params(returning_url, {
                'error': 'upstream_error',
            }), local=False)

        if token_response.get('error'):
            return request.redirect(self._append_query_params(returning_url, {
                'error': token_response.get('error'),
                'error_description': token_response.get('error_description') or '',
            }), local=False)

        access_token = token_response.get('access_token')
        if not access_token:
            return request.redirect(self._append_query_params(returning_url, {
                'error': 'missing_token',
            }), local=False)

        return request.redirect(self._append_query_params(returning_url, {
            'access_token': access_token,
            'state': consumer_state,
        }), local=False)

    @http.route('/api/social/youtube/1/refresh_token', type='http', auth='public', methods=['GET'], csrf=False)
    def refresh_youtube_token(self, db_uuid=None, refresh_token=None, **kwargs):
        client_id = self._icp().get_param('social_relay_service.youtube_client_id')
        client_secret = self._icp().get_param('social_relay_service.youtube_client_secret')

        if not refresh_token:
            return Response(json.dumps({'error': 'missing_refresh_token'}), mimetype='application/json')
        if not client_id or not client_secret:
            return Response(json.dumps({'error': 'youtube_missing_configuration'}), mimetype='application/json')

        try:
            response = requests.post(
                'https://oauth2.googleapis.com/token',
                data={
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                },
                timeout=10,
            )
            return Response(response.text, mimetype='application/json', status=response.status_code)
        except requests.RequestException:
            _logger.exception('YouTube refresh token call failed')
            return Response(json.dumps({'error': 'upstream_error'}), mimetype='application/json', status=502)

    def _jsonrpc_response(self, rpc_id, result=None, error=None, status=200):
        payload = {'jsonrpc': '2.0', 'id': rpc_id}
        if error is not None:
            payload['error'] = error
        else:
            payload['result'] = result
        return Response(json.dumps(payload), mimetype='application/json', status=status)

    def _jsonrpc_error(self, rpc_id, code, message, name='social_relay_service.Error', status=200):
        return self._jsonrpc_response(
            rpc_id,
            error={
                'code': code,
                'message': message,
                'data': {'name': name, 'message': message},
            },
            status=status,
        )

    @http.route('/api/social/twitter/1/get_signature', type='http', auth='public', methods=['POST'], csrf=False)
    def twitter_get_signature(self, **kwargs):
        try:
            payload = json.loads(request.httprequest.data or '{}')
        except json.JSONDecodeError:
            payload = {}

        rpc_id = payload.get('id')
        params = payload.get('params') or {}
        consumer_secret = (
            self._icp().get_param('social.twitter_consumer_secret_key')
            or self._icp().get_param('social_relay_service.twitter_consumer_secret')
        )
        if not consumer_secret:
            return self._jsonrpc_error(rpc_id, 1, 'twitter_consumer_secret_not_configured')

        method = params.get('method')
        url = params.get('url')
        oauth_token_secret = params.get('oauth_token_secret', '')
        sign_params = params.get('params') or {}

        if not method or not url or not isinstance(sign_params, dict):
            return self._jsonrpc_error(rpc_id, 2, 'invalid_signature_payload')

        signing_key = '&'.join([
            quote(str(consumer_secret or ''), safe='-._~'),
            quote(str(oauth_token_secret or ''), safe='-._~'),
        ])
        query = '&'.join([
            '%s=%s' % (
                quote(str(key), safe='-._~'),
                quote(str(sign_params[key]), safe='-._~'),
            )
            for key in sorted(sign_params.keys())
        ])
        base_string = '&'.join([
            str(method or '').upper(),
            quote(url, safe='-._~'),
            quote(query, safe='-._~'),
        ])
        digest = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
        signature = base64.b64encode(digest).decode()
        return self._jsonrpc_response(rpc_id, result=signature)

    @http.route('/iap/social_push_notifications/get_firebase_info', type='http', auth='public', methods=['GET'], csrf=False)
    def get_firebase_info(self, db_uuid=None, **kwargs):
        data = {
            'firebase_project_id': self._icp().get_param('social_relay_service.firebase_project_id') or '',
            'firebase_web_api_key': self._icp().get_param('social_relay_service.firebase_web_api_key') or '',
            'firebase_push_certificate_key': self._icp().get_param('social_relay_service.firebase_push_certificate_key') or '',
            'firebase_sender_id': self._icp().get_param('social_relay_service.firebase_sender_id') or '',
            'firebase_web_app_id': self._icp().get_param('social_relay_service.firebase_web_app_id') or '',
        }
        return Response(json.dumps(data), mimetype='application/json')

    @http.route('/iap/social_push_notifications/firebase_send_message', type='http', auth='public', methods=['POST'], csrf=False)
    def firebase_send_message(self, **kwargs):
        try:
            payload = json.loads(request.httprequest.data or '{}')
        except json.JSONDecodeError:
            payload = {}

        rpc_id = payload.get('id')
        params = payload.get('params') or {}
        tokens = params.get('tokens') or []

        # This endpoint is intentionally minimal: it acknowledges the batch.
        # Replace this with your provider call if you need to really dispatch notifications.
        _logger.info('social_relay_service received push batch: %s token(s)', len(tokens))
        return self._jsonrpc_response(rpc_id, result={'accepted': len(tokens)})
