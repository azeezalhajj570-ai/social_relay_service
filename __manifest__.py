# -*- coding: utf-8 -*-
{
    'name': 'Social Relay Service',
    'version': '18.0.1.0.0',
    'summary': 'Self-hosted relay endpoints for Odoo Social integrations',
    'category': 'Marketing/Social Marketing',
    'license': 'LGPL-3',
    'depends': ['base_setup', 'web'],
    'data': [
        'data/ir_config_parameter_data.xml',
        'views/res_config_settings_views.xml',
    ],
    'installable': True,
    'application': False,
}
