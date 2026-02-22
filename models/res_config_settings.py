# -*- coding: utf-8 -*-

from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    social_relay_facebook_add_accounts_url = fields.Char(
        string='Facebook Add Accounts URL Template',
        config_parameter='social_relay_service.facebook_add_accounts_url',
        help='Template supports {returning_url} and {db_uuid}.',
    )
    social_relay_instagram_add_accounts_url = fields.Char(
        string='Instagram Add Accounts URL Template',
        config_parameter='social_relay_service.instagram_add_accounts_url',
        help='Template supports {returning_url} and {db_uuid}.',
    )
    social_relay_youtube_add_accounts_url = fields.Char(
        string='YouTube Add Accounts URL Template',
        config_parameter='social_relay_service.youtube_add_accounts_url',
        help='Template supports {returning_url} and {db_uuid}.',
    )
    social_relay_twitter_add_accounts_url = fields.Char(
        string='Twitter Add Accounts URL Template',
        config_parameter='social_relay_service.twitter_add_accounts_url',
        help='Template supports {returning_url} and {db_uuid}.',
    )
    social_relay_linkedin_add_accounts_url = fields.Char(
        string='LinkedIn Add Accounts URL Template',
        config_parameter='social_relay_service.linkedin_add_accounts_url',
        help='Template supports {returning_url} and {db_uuid}.',
    )

    social_relay_youtube_client_id = fields.Char(
        string='YouTube OAuth Client ID',
        config_parameter='social_relay_service.youtube_client_id',
    )
    social_relay_youtube_client_secret = fields.Char(
        string='YouTube OAuth Client Secret',
        config_parameter='social_relay_service.youtube_client_secret',
    )

    social_relay_twitter_consumer_secret = fields.Char(
        string='Twitter Consumer Secret',
        config_parameter='social_relay_service.twitter_consumer_secret',
    )
    social_relay_twitter_consumer_key = fields.Char(
        string='Twitter Consumer Key',
        config_parameter='social_relay_service.twitter_consumer_key',
    )

    social_relay_firebase_project_id = fields.Char(
        string='Firebase Project ID',
        config_parameter='social_relay_service.firebase_project_id',
    )
    social_relay_firebase_web_api_key = fields.Char(
        string='Firebase Web API Key',
        config_parameter='social_relay_service.firebase_web_api_key',
    )
    social_relay_firebase_push_certificate_key = fields.Char(
        string='Firebase Push Certificate Key',
        config_parameter='social_relay_service.firebase_push_certificate_key',
    )
    social_relay_firebase_sender_id = fields.Char(
        string='Firebase Sender ID',
        config_parameter='social_relay_service.firebase_sender_id',
    )
    social_relay_firebase_web_app_id = fields.Char(
        string='Firebase Web App ID',
        config_parameter='social_relay_service.firebase_web_app_id',
    )
