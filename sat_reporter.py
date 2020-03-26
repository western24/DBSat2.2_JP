#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
import getopt
import datetime
import shlex
import string
import hashlib
import re
import traceback
import xml.etree.ElementTree as ET
import sat_analysis as sat

VERSION = '2.2 (September 2019)'

def db_identification(program):
    global collection_date
    global show_all_grants
    data = sat.get_data('date_and_release', 1)
    if data is None:
        sat.diag('Collection date not found')
        date_str = ''
    else:
        date_idx = sat.get_index('date_and_release', 'collection_date')
        collection_date = read_date(data[0][date_idx])
        date_str = format_date(collection_date)

    today_str = format_date(datetime.datetime.now())

    hash = hashlib.sha256()
#    for line in open(program):
#        hash.update(line.encode('utf-8', 'replace'))
    version = '%s - %s' % (VERSION, hash.hexdigest()[-4:])

    rows = (('Date of Data Collection', 'Date of Report', 'Reporter Version'),
        (date_str, today_str, version))

#    sat.table('Assessment Date & Time', rows, header=True)
    sat.table('アセスメント実施日時'.decode('utf-8'), rows, header=True)

    global con_type 
    data = sat.get_data('db_identity', 1)
    if data is None:
        sat.diag('Database identity data not found')
    else:
        name = sat.get_index('db_identity', 'name')
        platform = sat.get_index('db_identity', 'platform')
        dg_role = sat.get_index('db_identity', 'dg_role')
        logmode =  sat.get_index('db_identity', 'log_mode')
        created = sat.get_index('db_identity', 'created')
        created_str = format_date(read_date(data[0][created]))
        header = ['Name', 'Platform', 'Database Role', 'Log Mode', 'Created'] 
        values = [data[0][name], data[0][platform],
                  data[0][dg_role], data[0][logmode], created_str]

        pdb_data = sat.get_data('db_pdbs', 1)
        con_type = None
        con_type_str = None
        if pdb_data:
            pdb_name = sat.get_index('db_pdbs', 'name')
            con_id = sat.get_index('db_pdbs', 'con_id')
            if len(pdb_data) > 1:
                con_type = 'Root'
                con_type_str = 'Root'
            else:
                if show_all_grants == True:
                    con_type = 'PDB_COMPREHENSIVE'
                else:
                    con_type = 'PDB'
                con_type_str = 'PDB'
            container = '%s (%s:%d)' % (pdb_data[0][pdb_name], con_type_str,
                pdb_data[0][con_id])
            header.insert(1, 'Container (Type:ID)')
            values.insert(1, container)

#        sat.table('Database Identity', (header, values), header=True)
        sat.table('アセスメント対象データベース'.decode('utf-8'), (header, values), header=True)


def sec_feature_usage():
    global traditional_audit
    global pure_unified_audit
    pure_unified_audit = 'No'
    
    if target_db_version is None:
        sat.diag('Database release not found')

    sec_options = set()
    rows = []
    data = sat.get_data('user_account', 12)
    authen_type = sat.get_index('user_account', 'authentication_type')
    if data is not None and authen_type is not None:
#        rows = [['USER AUTHENTICATION', '']]
        rows = [['ユーザー認証'.decode('utf-8'), '']]

        if len([x for x in data if x[authen_type] == 'PASSWORD']) > 0:
#            rows += [['Password Authentication', 'Yes']]
            rows += [['パスワード認証'.decode('utf-8'), 'Yes']]
        else:
#            rows += [['Password Authentication', 'No']]
            rows += [['パスワード認証'.decode('utf-8'), 'No']]
	        
	if len([x for x in data if x[authen_type] == 'GLOBAL']) > 0:
            rows += [['Global Authentication', 'Yes']]
        else:
            rows += [['Global Authentication', 'No']]
	
	if len([x for x in data if x[authen_type] == 'EXTERNAL']) > 0:
            rows += [['External Authentication', 'Yes']]
        else:
            rows += [['External Authentication', 'No']]


    if rows is not None and len(rows) > 0:
        rows += [['', '']]
#        rows += [['AUTHORIZATION CONTROL', '']]
        rows += [['アクセス許可制御'.decode('utf-8'), '']]
    else:
#        rows = [['AUTHORIZATION CONTROL', '']]
        rows = [['アクセス許可制御'.decode('utf-8'), '']]

    if db_options_dict.get('Oracle Database Vault', False):
        rows += [['Database Vault', 'Yes']]
        sec_options.add('Database Vault')
    else:
        rows += [['Database Vault', 'No']]

    data = sat.get_data('privilege_capture', 1)
    if data is not None:
        if len(data) == 0:
            rows += [['Privilege Analysis', 'No']]
        else:
            rows += [['Privilege Analysis', 'Yes']]

    rows += [['', '']]
#    rows += [['ENCRYPTION', '']]
    rows += [['暗号化'.decode('utf-8'), '']]
    tblenc = False

    data = sat.get_data('encrypted_tablespace', 2)
    if data is not None:
        algo = sat.get_index('encrypted_tablespace', 'algo')

        if len([1 for x in data if len(x[algo]) > 0]) > 0:
            rows += [['Tablespace Encryption', 'Yes']]
            sec_options.add('Advanced Security')
            tblenc = True
        else:
            rows += [['Tablespace Encryption', 'No']]

    data = sat.get_data('encrypted_column', 1)
    if data is None or len(data) == 0:
        rows += [['Column Encryption', 'No']]
    else:
        rows += [['Column Encryption', 'Yes']]
        sec_options.add('Advanced Security')



    network_enc = False
    dict_sqlnet = parse_configfile('sqlnet.ora')
    if dict_sqlnet is not None:
        server_enc = dict_sqlnet.get('SQLNET.ENCRYPTION_SERVER', 'ACCEPTED')

        if server_enc.upper() in ('REQUIRED', 'REQUESTED'):
            network_enc = True
    dict_listener = {}
    if not network_enc:
        dict_listener = parse_configfile('listener.ora')

        if dict_listener:
            lsnr_protocols = get_listener_protocols(dict_listener)

            for x in lsnr_protocols:
                protocol = x[1]

                if protocol['TCPS'] > 0:
                    network_enc = True
                    break

    if network_enc:
        rows += [['Network Encryption', 'Yes']]
    else:
        if dict_sqlnet is not None or dict_listener:
           rows += [['Network Encryption', 'No']]

    rows += [['', '']]
#    rows += [['AUDITING', '']]
    rows += [['監査'.decode('utf-8'), '']]

    data = sat.get_data('unified_audit_policy', 1)
    if data is not None:
        state = sat.get_index('unified_audit_policy', 'state')
        enabled_policies = [x for x in data if x[state] == 'Enabled']
        if len(enabled_policies) > 0:
            rows += [['Unified Audit', 'Yes']]
        else:
            rows += [['Unified Audit', 'No']]

    data = sat.get_data('fine_grained_audit', 1)
    if  data is None or len(data) == 0:
        rows += [['Fine Grained Audit', 'No']]
    else:
        rows += [['Fine Grained Audit', 'Yes']]

    if db_options_dict.get('Unified Auditing', False):
        traditional_audit = 'N/A'
        pure_unified_audit = 'Yes'
    else:
        sdata = sat.get_data('statement_audit', 1)
        odata = sat.get_data('object_audit', 1)
        pdata = sat.get_data('privilege_audit', 1)
        if ((sdata is not None and len(sdata) != 0) or \
                (odata is not None and len(odata) != 0) or \
                (pdata is not None and len(pdata) != 0)):
            traditional_audit = 'Yes'
        else:
            traditional_audit = 'No'
    rows += [['Traditional Audit', traditional_audit]]

    rows += [['', '']]
    rows += [['FINE-GRAINED ACCESS CONTROL', '']]

    data = sat.get_data('vpd_policy', 1)
    if data is None or len(data) == 0:
        rows += [['Virtual Private Database', 'No']]
    else:
        rows += [['Virtual Private Database', 'Yes']]

    data = sat.get_data('ras_policy', 1)
    if data is not None:
        if len(data) == 0:
            rows += [['Real Application Security', 'No']]
        else:
            rows += [['Real Application Security', 'Yes']]

    if db_options_dict.get('Oracle Label Security', False):
        rows += [['Label Security', 'Yes']]
        sec_options.add('Label Security')
    else:
        rows += [['Label Security', 'No']]

    data = sat.get_data('redaction_policy', 1)
    if data is not None:
        if len(data) == 0:
            rows += [['Data Redaction', 'No']]
        else:
            rows += [['Data Redaction', 'Yes']]
            sec_options.add('Advanced Security')

    scol = sat.get_data('tsdp_sensitive_column', 1)
    pcol = sat.get_data('tsdp_protected_column', 1)
    tsdp_pol = sat.get_data('tsdp_policy', 1)
    if scol is not None or pcol is not None or tsdp_pol is not None:
        if tsdp_pol is not None:
            policy = sat.get_index('tsdp_policy', 'policy_name')
            plist = [x[policy] for x in tsdp_pol if x[policy] != 'REDACT_AUDIT']
        else:
            plist = []

        if ((scol is not None and len(scol) > 0) or
            (pcol is not None and len(pcol) > 0) or
            len(plist) > 0):
            rows += [['Transparent Sensitive Data Protection', 'Yes']]
        else:
            rows += [['Transparent Sensitive Data Protection', 'No']]


    data = sat.get_data('db_version', 1)
    if data is None:
        sat.diag('Database version data not found')
    else:
        vrows = [data[0],]
        vrows.append(['Security options used: ' + 
            join_list(sorted(sec_options)),])
#        sat.table('Database Version', vrows, header=False)
        sat.table('データベースバージョン'.decode('utf-8'), vrows, header=False)

    sat.table('セキュリティ機能利用状況'.decode('utf-8'), [['Feature', 'Currently Used']] + rows,
        header=True, alignment=['left', 'center'])


def patch_checks():
    opatch_data = sat.get_data('opatch_inventory', 1)
    history_data = sat.get_data('registry_history', 12)
    spatch12_data = sat.get_data('registry_sqlpatch', 2)
    spatch18_data = sat.get_data('registry_sqlpatch18', 1)

    inventory_list = []
    history_list = []
    bundle_date = None
    interim_date = None

    if opatch_data:
        for idx, x in enumerate(opatch_data):
            if 'Created on' in x[0]:
                str = x[0]
                date_str = str[str.index('Created on')+11:str.index(',')]
                created_date = read_date(date_str, '%d %b %Y') 
                desc = opatch_data[idx-1][0].upper()
                if 'DATABASE PATCH SET UPDATE' in desc or \
                  'DATABASE BUNDLE PATCH' in desc or \
                  'DATABASE RELEASE UPDATE' in desc:
                    patch_id = opatch_data[idx-2][0].split()[-1]
                    patch_str = 'Patch ID (Comprehensive): %s (created %s)' % \
                                (patch_id, format_date(created_date, '%B %Y'))
                    inventory_list.append(patch_str)
                    bundle_date = max_date(bundle_date, created_date)
                elif 'Unique Patch ID' in opatch_data[idx-1][0]:
                    patch_id = opatch_data[idx-1][0].split()[-1]
                    patch_str = 'Patch ID: %s (created %s)' % \
                                (patch_id, format_date(created_date, '%B %Y'))
                    inventory_list.append(patch_str)
                    interim_date = max_date(interim_date, created_date)

    if spatch18_data:
        action_time = sat.get_index('registry_sqlpatch18', 'action_time')
        action = sat.get_index('registry_sqlpatch18', 'action')
        version = sat.get_index('registry_sqlpatch18', 'target_version')
        patch_type = sat.get_index('registry_sqlpatch18', 'patch_type')
        reldate = sat.get_index('registry_sqlpatch18', 'target_build_timestamp')
        description = sat.get_index('registry_sqlpatch18', 'description')

        for x in spatch18_data:
            if x[action] == 'APPLY' or x[action] == 'ROLLBACK':
                action_date = read_date(x[action_time])
                patch_action = 'Action time: %s\n' % format_date(action_date)
                patch_action += 'Action: %s\n' % x[action]
                patch_action += 'Version: %s\n' % x[version]
                patch_action += 'Description: %s\n' % x[description]
                history_list.append(patch_action)
                if patch_type == 'INTERIM':
                    interim_date = max_date(interim_date, read_date(x[reldate]))
                else:
                    bundle_date = max_date(bundle_date, read_date(x[reldate]))

    elif spatch12_data:
        action_time = sat.get_index('registry_sqlpatch', 'action_time')
        action = sat.get_index('registry_sqlpatch', 'action')
        version = sat.get_index('registry_sqlpatch', 'version')
        bundle_series = sat.get_index('registry_sqlpatch', 'bundle_series')
        bundle_id = sat.get_index('registry_sqlpatch', 'bundle_id')
        description = sat.get_index('registry_sqlpatch', 'description')

        for x in spatch12_data:
            if x[action] == 'APPLY' or x[action] == 'ROLLBACK':
                action_date = read_date(x[action_time])
                patch_action = 'Action time: %s\n' % format_date(action_date)
                patch_action += 'Action: %s\n' % x[action]
                patch_action += 'Version: %s\n' % x[version]
                patch_action += 'Bundle series: %s\n' % x[bundle_series]
                patch_action += 'Description: %s\n' % x[description]
                history_list.append(patch_action)
                if x[bundle_series]:
                    patch_date = read_date('%06d' % x[bundle_id], '%y%m%d')
                    bundle_date = max_date(bundle_date, patch_date)

    elif history_data:
        action_time = sat.get_index('registry_history', 'action_time')
        action = sat.get_index('registry_history', 'action')
        namespace = sat.get_index('registry_history', 'namespace')
        version = sat.get_index('registry_history', 'version')
        bundle_series = sat.get_index('registry_history', 'bundle_series')
        id = sat.get_index('registry_history', 'id')
        comments = sat.get_index('registry_history', 'comments')

        for x in history_data:
            if x[action] == 'APPLY' or x[action] == 'ROLLBACK':
                action_date = read_date(x[action_time])
                patch_action = 'Action time: %s\n' % format_date(action_date)
                patch_action += 'Action: %s\n' % x[action]
                patch_action += 'Namespace: %s\n' % x[namespace]
                patch_action += 'Version: %s\n' % x[version]
                patch_action += 'Bundle series: %s\n' % x[bundle_series]
                patch_action += 'Comments: %s\n' % x[comments]
                history_list.append(patch_action)
                patch_date = read_date('%06d' % x[id], '%y%m%d')
                if x[bundle_series]:
                    bundle_date = max_date(bundle_date, patch_date)
                else:
                    interim_date = max_date(interim_date, patch_date)

    details = ''
    bundle_delta = days_since(bundle_date)
    if bundle_delta is not None:
        details += 'Latest comprehensive patch: %s (%d days ago)\n' % \
            (format_date(bundle_date, '%b %d %Y'), bundle_delta)
    interim_delta = days_since(interim_date)
    if interim_delta is not None:
        details += 'Latest interim patch: %s (%d days ago)\n' % \
            (format_date(interim_date, '%b %d %Y'), interim_delta)
    if details:
        details += '\n'
    if len(inventory_list) > 0: 
       details += 'Binary Patch Inventory: \n'
       details += join_list(inventory_list, '\n') + '\n\n'
    if len(history_list) > 0:
       details += 'SQL Patch History: \n'
       details += join_list(history_list, '\n')

    if bundle_delta is not None and bundle_delta < 120:
        severity = sat.SEV_OK
#        summary = 'Latest comprehensive patch has been applied.'
        summary = '最新のPSUが既に適用されています'.decode('utf-8')
    elif interim_delta is not None and interim_delta < 90:
        severity = sat.SEV_UNKNOWN
#        summary = 'Some patches applied within the last quarter.'
        summary = 'いくつかの適用されたパッチは直前の四半期以内です '.decode('utf-8')
    else:
        severity = sat.SEV_HIGH
#        summary = 'Latest comprehensive patch not found.'
        summary = '最新のPSUが見つかりません '.decode('utf-8')

#    remarks = 'It is vital to keep the database software up-to-date ' + \
#        'with security fixes as they are released. ' + \
#        'Oracle issues comprehensive patches in the form of Release ' + \
#        'Updates, Patch Set Updates, and Bundle Patches on a regular ' + \
#        'quarterly schedule. These updates should be applied as soon as ' + \
#        'they are available.'

    remarks = '最新のSecurity Patchを適用してデータベースを最新に保つことは ' + \
        '非常に重要です。Oracle Databaseは、Patch Set Updates (PSU)を定期的にリリースしており、' + \
        '最新のPSUをできる限り早く適用して下さい。'

    refs = {'CIS': 'Recommendation 1.1', 'STIG': 'Rule SV-76029r2'}
    if details:
       sat.finding('パッチ適用状況'.decode('utf-8'), 'INFO.PATCH', summary,
          severity, details, remarks.decode('utf-8'), refs)
     

def user_section():
    profile_dict = get_profile_data()
    user_account()
    system_default_tablespace()
    sample_schema()
    if con_type is not None and con_type == 'PDB':
      inactive_user(profile_dict, local_acct_profiles)
    else:
      inactive_user(profile_dict, acct_profiles)
    expired_user()
    case_sensitive_password()
    user_with_default_password()
    sqlnet_allowed_logon_version()
    user_password_version()
    user_params()
    user_profiles(profile_dict)
    if con_type == 'PDB':
       user_password(profile_dict, local_acct_profiles)
       user_login(profile_dict, local_acct_profiles)
       password_verify_function(profile_dict, local_acct_profiles)
    else:
       user_password(profile_dict, acct_profiles)
       user_login(profile_dict, acct_profiles)
       password_verify_function(profile_dict, acct_profiles)

def user_account():
    data = sat.get_data('user_account', 1)
    if data is None:
        sat.diag('Skipped User Accounts')
        return
    user_name = sat.get_index('user_account', 'username')
    user_profile = sat.get_index('user_account', 'profile')
    status = sat.get_index('user_account', 'status')
    d_tab_space = sat.get_index('user_account', 'default_tablespace')
    t_tab_space = sat.get_index('user_account', 'temporary_tablespace')
    auth_type = sat.get_index('user_account', 'authentication_type')
    external_name = sat.get_index('user_account', 'external_name') 

    if not check_oracle_accts:
        sat.info('Note: Predefined Oracle accounts which are locked are '
             'not included in this report. To include all user accounts, '
             'run the report with the -a option.')

    rows = []
    for x in data:
        if x[user_name] not in acct_profiles:
            continue
        if x[user_name] in oracle_users:
            oracle = 'Yes'
        else:
            oracle = 'No'
        if auth_type:
            if external_name and len(x[external_name]) > 0:
              row = [x[user_name], x[status], x[user_profile],
                     x[d_tab_space], oracle, 
                     x[auth_type] + ': ' + x[external_name]]
            else:
              row = [x[user_name], x[status], x[user_profile],
                     x[d_tab_space], oracle, x[auth_type]]
        else:
            row = [x[user_name], x[status], x[user_profile],
                   x[d_tab_space], oracle]
        rows.append(row)

    if auth_type:
        columns = [['User Name', 'Status', 'Profile', 'Tablespace',
                    'Oracle Defined', 'Auth Type']]
        alignment = ['left', 'left', 'left', 'left', 'center', 'left']
    else:
        columns = [['User Name', 'Status', 'Profile', 'Tablespace',
                    'Oracle Defined']]
        alignment = ['left', 'left', 'left', 'left', 'center']

#    sat.table('User Accounts', columns+rows, header=True, alignment=alignment)
    sat.table('ユーザーアカウント'.decode('utf-8'), columns+rows, header=True, alignment=alignment)

def system_default_tablespace():
    data = sat.get_data('user_account', 1)
    if data is None:
        sat.diag('Skipped Default Tablespaces')
        return

    username = sat.get_index('user_account', 'username')
    d_tab_space = sat.get_index('user_account', 'default_tablespace')
    t_tab_space = sat.get_index('user_account', 'temporary_tablespace')

    system_users = []
    sysaux_users = []
    for x in data:
        if x[username] in oracle_users:
            continue
        if x[d_tab_space] == 'SYSTEM' or x[t_tab_space] == 'SYSTEM':
            system_users.append(x[username])
        elif x[d_tab_space] == 'SYSAUX' or x[t_tab_space] == 'SYSAUX':
            sysaux_users.append(x[username])

    total_num = len(system_users) + len(sysaux_users)

    if total_num > 0:
        severity = sat.SEV_MEDIUM
        summary = 'Found ' + sing_plural(total_num, 'user', 'users') + \
                  ' using SYSTEM or SYSAUX tablespace.'
        details = 'Tablespace SYSTEM: ' + join_list(system_users) + '\n'
        details += 'Tablespace SYSAUX: ' + join_list(sysaux_users) + '\n'
    else:
        severity = sat.SEV_OK
#        summary = 'No user data is stored in SYSTEM and SYSAUX tablespace by default.'
        summary = 'デフォルトで SYSTEM・SYSAUX 表領域にデータを格納するユーザはいません'.decode('utf-8')
        details = None

#    remarks = 'The SYSTEM and SYSAUX tablespaces are reserved for ' + \
#        'Oracle-supplied user accounts. To avoid a possible ' + \
#        'denial of service caused by exhausting these resources, ' + \
#        'regular user schemas should not use these tablespaces. '
    remarks = 'SYSTEMとSYSAUX表領域は、Oracle Databaseの管理ユーザ用に用意された' + \
        '表領域です。表領域を使い尽くすことによるサービスの停止を避けるために、' + \
        '通常のユーザ・スキーマがこの領域を使用することは避けて下さい。'

    refs = {'STIG': 'Rule SV-75949r2, SV-75951r3' }
    sat.finding('SYSTEM、SYSAUX表領域を利用しているユーザ・スキーマ'.decode('utf-8'),
        'USER.TBLSPACE', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def sample_schema():
    data = sat.get_data('user_account', 1)
    if data is None:
        sat.diag('Skipped Sample Schemas')
        return
    name = sat.get_index('user_account', 'username')

    sample_schema_list = ['SCOTT','HR', 'OE', 'SH', 'PM', 'IX', \
                  'ADAMS', 'BLAKE', 'CLARK', 'BI']

    user_list = [x[name] for x in data if x[name] in sample_schema_list]

    if len(user_list) > 0:
        severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_OK

    if len(user_list) > 0:
        summary = 'Found ' + sing_plural(len(user_list), 
                                         'sample schema.', 'sample schemas.')
        details = 'Sample schemas: ' + join_list(user_list) + '\n';
    else:
#        summary = 'No sample schemas found.'
        summary = 'サンプルスキーマは見つかりませんでした。'.decode('utf-8')
        details = None

#    remarks = 'Sample schemas are well-known accounts provided by ' + \
#        'Oracle to serve as simple examples for developers. They ' + \
#        'generally serve no purpose in a production database and ' + \
#        'should be removed because they unnecessarily increase ' + \
#        'the attack surface of the database.'
    remarks = 'サンプルスキーマは、開発者へ簡単なサンプルを提供するために用意されており、' + \
        '良く知られています。それらは一般的に本番システムでは不要であり' + \
        '極力取り除くべきです。なぜなら、それはデータベースへの攻撃の糸口を不必要に' + \
        '増加させるためです。'

    refs = {'CIS': 'Recommendation 1.3', 'STIG': 'Rule SV-76167r3'}

#    sat.finding('Sample Schemas', 'USER.SAMPLE', summary,
#        severity, details, remarks, refs)
    sat.finding('サンプルスキーマ'.decode('utf-8'), 'USER.SAMPLE', summary,
        severity, details, remarks.decode('utf-8'), refs)

def inactive_user(profiles, users):

    severity = sat.SEV_OK
    summary = ''
    details = ''

    if profiles is not None:
       profile_list, user_list, exempt_prof_list = \
           profile_unset(profiles, users, 'INACTIVE_ACCOUNT_TIME', ('day', 'days'))
       if len(user_list) > 0:
           severity = sat.SEV_LOW
           summary += 'Found ' + sing_plural(len(user_list), 'user account', 
                                             'user accounts') + \
                      ' that would remain open even if' +\
                      ' inactive. '
           details += 'Users with unlimited INACTIVE_ACCOUNT_TIME: ' + \
                      join_list(user_list) + '\n'
       else:
           summary += 'All user accounts will eventually lock when inactive.'

    data = sat.get_data('user_account', 21)
    if data is None or collection_date is None:
        if target_db_version >= '12.1':
            sat.diag('Skipped Inactive Users')
        return

    user_name = sat.get_index('user_account', 'username')
    status = sat.get_index('user_account', 'status')
    created = sat.get_index('user_account', 'created')
    last_login = sat.get_index('user_account', 'last_login')
    common = sat.get_index('user_account', 'common')

    user_list = []
    for x in data:
        if x[user_name] not in acct_profiles:
            continue
        if x[status] not in ('OPEN', 'EXPIRED', 'EXPIRED(GRACE)'):
            continue
        if con_type == 'PDB' and common != None and x[common] == 'YES':
            continue
        create_date = datetime.datetime.strptime(x[created],
                            '%d-%m-%Y %H:%M')
        delta = collection_date - create_date
        if delta.days < 30:
            continue
        if len(x[last_login]) == 0:
            user_list.append(x[user_name])
        else:
            last_login_date = datetime.datetime.strptime(
                                            x[last_login], '%d-%m-%Y %H:%M')
            delta = collection_date - last_login_date
            if delta.days >= 30:
                user_list.append(x[user_name])

    if len(user_list) > 0:
        severity = max(severity, sat.SEV_LOW)
        summary += 'Found ' + sing_plural(len(user_list), 
                              'unlocked user', 'unlocked users') + \
                  ' inactive for more than 30 days.'
        details += 'Inactive users: ' + join_list(user_list)
    else:
        severity = max(severity, sat.SEV_OK)
#        summary += 'No unlocked users inactive for more than 30 days found.'
        summary += '30日以上放置されたロックされていないユーザーはいませんでした。'.decode('utf-8')
        if len(details) == 0:
           details = None

#    remarks = 'If a user account is no longer in use, it increases the ' + \
#        'attack surface of the system unnecessarily while ' + \
#        'providing no corresponding benefit. Furthermore, ' + \
#        'unauthorized use is less likely to be noticed when no ' + \
#        'one is regularly using the account. Accounts that have ' + \
#        'been unused for more than 30 days should be ' + \
#        'investigated to determine whether they should remain ' + \
#        'active. ' + \
#        'A solution is to set INACTIVE_ACCOUNT_TIME in the profiles ' + \
#        'assigned to users to automatically lock accounts which have ' + \
#        'not logged in to the database instance in a specified number of ' + \
#        'days. It is also recommended to audit infrequently used accounts ' + \
#        'for unauthorized activities.'
    remarks = 'もしユーザーアカウントが既に使用されていない場合、' + \
        'それは不要なだけでなく、システムへの攻撃の糸口を不必要に増加させます。' + \
        'さらに定期的に利用されていないアカウントでは不正利用に気付きにくいです。' + \
        '30日以上の未使用になっているアカウントはアクティブのままにするかどうか ' + \
        '考慮する必要があります。' + \
		'解決策は、指定された日数内にデータベースインスタンスにログイン' + \
		'していないアカウントを自動的にロックするように、ユーザーに割り当てられた' + \
		'プロファイルにINACTIVE_ACCOUNT_TIMEを設定することです。' + \
		'まれに使用されているアカウントを不正な活動について監査することもお勧めします。'

    if details is not None and con_type == 'PDB_COMPREHENSIVE':
#        remarks += '\nCommon users cannot be altered in a PDB.\n'
        remarks += '\n一般的なユーザーはPDBで変更できません。\n'

    refs = {'STIG': 'Rule SV-76207r2'}

#    sat.finding('Inactive Users', 'USER.INACTIVE', summary,
#        severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('アクティブでないユーザー'.decode('utf-8'), 'USER.INACTIVE', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def case_sensitive_password():
    checked, num_issues, details = \
        param_should('SEC_CASE_SENSITIVE_LOGON', 'TRUE')

    if num_issues > 0:
        severity = sat.SEV_HIGH
#        summary = 'Case-sensitive passwords are not used.'
        summary = 'パスワードで大文字小文字を区別していません。'.decode('utf-8')
    else:
        severity = sat.SEV_OK
#        summary = 'Case-sensitive passwords are used.'
        summary = 'パスワードで大文字小文字を区別しています。'.decode('utf-8')

#    remarks = 'Case-sensitive passwords are recommended because ' + \
#        'including both upper and lower-case letters greatly ' + \
#        'increases the set of possible passwords that must be ' + \
#        'searched by an attacker who is attempting to guess a ' + \
#        'password by exhaustive search. Setting ' + \
#        'SEC_CASE_SENSITIVE_LOGON to TRUE ensures that the ' + \
#        'database distinguishes between upper and lower-case ' + \
#        'letters in passwords.'
    remarks = 'パスワードでは大文字小文字を区別することが推奨されます。' + \
        '大小文字を含むことで、攻撃者がパスワードを推測して攻撃しなければならない' + \
        'パスワードのリストが劇的に増加します。SEC_CASE_SENSITIVE_LOGONパラメータをTRUEにすることで' + \
        'データベースはパスワードの大小文字を区別するようになります。'

    refs = {'CIS': 'Recommendation 2.2.12'}

#    sat.finding('Case-Sensitive Passwords', 'USER.CASE', summary,
#        severity, details, remarks, refs)
    sat.finding('パスワードの大文字小文字の区別'.decode('utf-8'), 'USER.CASE', summary,
        severity, details, remarks.decode('utf-8'), refs)

def expired_user():
    data = sat.get_data('user_account', 1)
    if data is None or collection_date is None:
        sat.diag('Skipped Expired Passwords')
        return
    user_name = sat.get_index('user_account', 'username')
    status = sat.get_index('user_account', 'status')
    expiry_date = sat.get_index('user_account', 'expiry_date')

    user_list = []
    for x in data:
        if x[user_name] not in acct_profiles:
            continue
        if x[status] not in ('OPEN', 'EXPIRED', 'EXPIRED(GRACE)'):
            continue
        if len(x[expiry_date]) > 0:
            exp_date = datetime.datetime.strptime(
                                            x[expiry_date], '%d-%m-%Y %H:%M')
            delta = collection_date - exp_date
            if delta.days >= 30:
                user_list.append(x[user_name])

    if len(user_list) > 0:
        severity = sat.SEV_LOW
        summary = 'Found ' + sing_plural(len(user_list), 'unlocked user', 
                                                         'unlocked users') + \
                  ' with password expired for more than 30 days.'
        details = 'Users with expired passwords: ' + join_list(user_list)
    else:
        severity = sat.SEV_OK
#        summary = 'No unlocked users found with password expired ' + \
#                  'for more than 30 days.'
        summary = '30日以上放置されたパスワードが期限切れのユーザーはいませんでした。'.decode('utf-8')
        details = None

#    remarks = "Password expiration is used to ensure that users change " \
#        "their passwords on a regular basis. If a user's " \
#        "password has been expired for more than 30 days, it " \
#        "indicates that the user has not logged in for at least " \
#        "that long. Accounts that have been unused for an " \
#        "extended period of time should be investigated to " \
#        "determine whether they should remain active."
    remarks = 'パスワードの有効期限切れは、ユーザが定期的にパスワードを変更することを' + \
        '確実にするために使用されます。もしユーザのパスワードが30日を経過して期限切れになったら' + \
        'ユーザは少なくともその期間まったくログインしていなかったことを示します。' + \
        '長期間使用していないアカウントは、アクティブのままにするかどうか' + \
        '考慮する必要があります。'

    if details is not None and con_type == 'PDB_COMPREHENSIVE':
#        remarks += '\nCommon users cannot be altered in a PDB.\n'
        remarks += '\n一般的なユーザーはPDBで変更できません。\n'

#    sat.finding('Users with Expired Passwords', 'USER.EXPIRED', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('パスワードが期限切れのユーザー'.decode('utf-8'), 'USER.EXPIRED', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))

def user_with_default_password():
    data = sat.get_data('user_with_default_password', 1)
    if data is None:
        sat.diag('Skipped Default Passwords')
        return
    account_open = sat.get_index('user_with_default_password', 'account_open')
    user_name = sat.get_index('user_with_default_password', 'username')

    open_list = [x[user_name] for x in data if x[account_open]
             and x[user_name] in acct_profiles]

    if len(open_list) > 0:
        severity = sat.SEV_HIGH
        summary = 'Found ' + \
                  sing_plural(len(open_list), 'unlocked user account',
                                              'unlocked user accounts') + \
                  ' with default password.'
        details = 'Users with default password: ' + join_list(open_list) + '\n'
    else:
        severity = sat.SEV_OK
#        summary = 'No unlocked user accounts are using default password.'
        summary = 'ロック解除されたユーザーアカウントはデフォルトのパスワードを使用していません'.decode('utf-8')
        details = None

#    remarks = 'Default passwords for predefined Oracle accounts are well ' + \
#        'known and provide a trivial means of entry for attackers. ' + \
#        'Well-known passwords for locked accounts should be changed as well.'
    remarks = '事前定義されたアカウントのデフォルトのパスワードは ' + \
        'よく知られ、攻撃者にとっての足かがりの手段になります。' + \
        'よく知られているパスワードは、ロックされているアカウントも含めて変更しておくことが求められます。'

    if details is not None and con_type == 'PDB_COMPREHENSIVE':
#        remarks += '\nCommon users cannot be altered in a PDB.\n'
        remarks += '\n一般的なユーザーはPDBで変更できません。\n'

    refs = {'CIS': 'Recommendation 1.2', 'STIG': 'Rule SV-76031r1, SV-76339r1' }
    
#    sat.finding('Users with Default Passwords', 'USER.DEFPWD', summary,
#        severity, details, remarks, refs)
    sat.finding('デフォルトのパスワードを利用しているユーザー'.decode('utf-8'), 'USER.DEFPWD', summary,
        severity, details, remarks.decode('utf-8'), refs)

def sqlnet_allowed_logon_version():
    dict = parse_configfile('sqlnet.ora')
    if dict is None or target_db_version is None:
        sat.diag('Skip Allowed Logon Version check') 
        return

    if target_db_version >= '12.1.0.2':
        para_name = 'ALLOWED_LOGON_VERSION_SERVER'
        default_value = '12'
        required_version = '12a'
    elif target_db_version >= '12':
        para_name = 'ALLOWED_LOGON_VERSION_SERVER'
        default_value = '11'
        required_version = '12'
    elif target_db_version >= '11':
        para_name = 'ALLOWED_LOGON_VERSION'
        default_value = '8'
        required_version = '12'
    elif target_db_version >= '10':
        para_name = 'ALLOWED_LOGON_VERSIONS'
        default_value = '(10, 9, 8)'
        required_version = '10'
    else:
        sat.diag('Skip Allowed Logon Version check')
        return

    issue, details = network_parameter(dict=dict,
                                       para_name='SQLNET.'+para_name,
                                       unset_ok=True,
                                       default_value=default_value,
                                       required_value=required_version,
                                       forbidden_value=None,
                                       case_sensitive=True)

    if issue:
        severity = sat.SEV_LOW
#        summary = 'Minimum client version is not configured correctly.'
        summary = '最小限のクライアントバージョンが正しく構成されていません。'.decode('utf-8')
    else:
        severity = sat.SEV_OK
#        summary = 'Minimum client version is configured correctly.'
        summary = '最小限のクライアントバージョンが正しく構成されています。'.decode('utf-8')

#    remarks = 'Over time, Oracle releases have added support for ' + \
#        'increasingly secure versions of the algorithm used for ' + \
#        'password authentication of user accounts. In order to remain ' + \
#        'compatible with older client software, the database ' + \
#        'continues to support previous password versions ' + \
#        'as well. The sqlnet.ora parameter ' + para_name + ' determines ' + \
#        'the minimum password version that the database will accept. ' + \
#        'For maximum security, ' + \
#        'this parameter should be set to the highest value supported ' + \
#        'by the database once all client systems have been upgraded.'
    remarks = '時代に沿ってOracleはアカウント認証のパスワードに使用されているアルゴリズム' + \
        'を安全なバージョンへと徐々に対応しています。また、古いソフトウェアの互換性を残すた' + \
        'めに、Oracle Databaseは以前のパスワードのバージョンもサポートしています。' + \
        'sqlnet.oraにある' + para_name + 'パラメータは、Oracle Databaseが受け' + \
        '入れるパスワードのバージョンを決定します。より安全にするためには、必要に応じてク' + \
        'ライアントをアップグレードし、このパラメータを高い値に設定することです。'

    refs = { 'STIG': 'Rule SV-76025r2' }
#    sat.finding('Minimum Client Authentication Version', 'USER.AUTHVERS',
#        summary, severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('クライアント認証受け入れの最低バージョン'.decode('utf-8'), 'USER.AUTHVERS',
        summary, severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def user_password_version():
    data = sat.get_data('user_account', 11)
    if data is None or target_db_version is None:
        sat.diag('Skipped User Account Verifiers')
        return

    name = sat.get_index('user_account', 'username')
    versions = sat.get_index('user_account', 'password_versions')
    authen_type = sat.get_index('user_account', 'authentication_type')

    outdated_list = []
    http_list = []

    if target_db_version >= '12.1.0.2':
        latest_verifier = '12C'
    elif target_db_version >= '11':
        latest_verifier = '11G'
    elif target_db_version >= '10':
        latest_verifier = '10G'
    else:
        latest_verifier = ''
        sat.diag('Skipped User Account Verifiers')

    pw_users = [x for x in data if x[name] in acct_profiles]
    if authen_type is not None:
        pw_users = [x for x in pw_users if x[authen_type] not in \
                    ('EXTERNAL', 'GLOBAL', 'NONE')]
    for x in pw_users:
        if latest_verifier not in x[versions]:
            outdated_list.append(x[name] + '(' + x[versions] + ')')
        if 'HTTP' in x[versions]:
            http_list.append(x[name])

    details = 'Database supports password versions up to ' + \
        latest_verifier.lower() + '.\n'

    severity = sat.SEV_OK
    details += 'Users authenticated using the prior weaker password verifiers: ' + \
        join_list(outdated_list) + '\n'
    if len(outdated_list) > 0:
        severity = sat.SEV_MEDIUM
        summary = 'Found ' + sing_plural(len(outdated_list), 
                                         'user account', 'user accounts') + \
                  ' requiring updated password verifiers. '
    else:
        summary = 'All user accounts are authenticated using the latest ' + \
                  'password verifier version. '

    details += '\n' + 'Users with HTTP verifiers: ' + \
        join_list(http_list) + '\n'
    if len(http_list) > 0:
        if severity == sat.SEV_OK:
            severity = sat.SEV_HIGH
        summary += 'Found ' + sing_plural(len(http_list), 
                                         'account', 'accounts') + \
                  ' with HTTP password verifiers.'
    else:
        summary += ' No user accounts have HTTP verifiers. '

#    remarks = 'For each user account, the database may store multiple ' + \
#        'verifiers, which are hashes of the user password. ' + \
#        'Each verifier supports a different version of the password ' + \
#        'authentication algorithm. Every user account should ' + \
#        'include a verifier for the latest password version supported by ' + \
#        'the database so that the user can be authenticated using ' + \
#        'the latest algorithm supported by the client. When all clients ' + \
#        'have been updated, the security of user accounts can be ' + \
#        'improved by removing the obsolete verifiers. ' + \
#        'HTTP password verifiers are used for XML Database authentication. ' + \
#        'Use the ALTER USER command to remove these verifiers from user ' + \
#        'accounts that do not require this access.'
    remarks = 'それぞれのユーザーアカウントのために、データベースは複数のパスワードのハッシュ' + \
        '値の認証情報を保持しています。また、それぞれの認証情報は、異なるパスワード' + \
        '認証アルゴリズムをサポートしています。' + \
        'すべてのユーザアカウントは、クライアントがサポートする最新のアルゴリズムを使用して認証できるよう' + \
        'に、データベースでサポートされている最新パスワード' + \
        'バージョンの認証情報を含める必要があります。' + \
        'すべてのクライアントがアップグレードされた時、古い認証情報が取り去られることによって' + \
        'ユーザーアカウントのセキュリティは向上します。また、HTTPパスワード認証情報はXML データ' + \
        'ベース認証に使われます。このアクセスを必要としないユーザーアカウントから、これら' + \
        'の認証情報を削除するには、ALTER USERコマンドを使用します'

    if len(outdated_list) > 0 or len(http_list) > 0:
         if con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommon users cannot be altered in a PDB.\n'
             remarks += '\n一般的なユーザーはPDBで変更できません。\n'

#    sat.finding('Password Verifiers', 'USER.VERIFIER', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('パスワード認証情報'.decode('utf-8'), 'USER.VERIFIER', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))


def user_params():
    checked, num_issues, details = \
        param_should_not('SEC_MAX_FAILED_LOGIN_ATTEMPTS', '0', 'not zero')
    checked, num_issues, details = \
        param_should('RESOURCE_LIMIT', 'TRUE', checked, num_issues, details)

    if checked == 0:
        sat.diag('Skipped User Parameter Check')
        return

    summary = param_check_summary(checked, num_issues)

    if num_issues > 0:
        severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_OK

#    remarks = "SEC_MAX_FAILED_LOGIN_ATTEMPTS configures the maximum " \
#        "number of failed login attempts in a single session before " \
#        "the connection is closed. This is independent of the user " \
#        "profile parameter FAILED_LOGIN_ATTEMPTS, which controls " \
#        "locking the user account after multiple failed login attempts. \n" \
#        "Not controlling failed login attempts before closing the " \
#        "connection and locking accounts after a number of failed logins, " \
#        "opens the door for successful brute-force login attacks and the " \
#        "occurrence of Denial-of-Service.\n" \
#        "RESOURCE_LIMIT should be set to TRUE to enable enforcement " \
#        "of any resource constraints set in user profiles."

    remarks = 'SEC_MAX_FAILED_LOGIN_ATTEMPTSパラメータはひとつのセッションで' + \
        'コネクションを切断するまでに何回のログイン試行失敗を許容するかを設定します。' + \
        '複数回のログイン試行失敗後にユーザーアカウントをロックする' + \
        'ユーザープロファイルのFAILED_LOGIN_ATTEMPTSパラメータとは独立していています。 \n' + \
		'接続を閉じる前のログイン試行失敗や複数回のログイン試行失敗後のアカウントのロックを制御しないと、' + \
		'ブルートフォース攻撃が成功し、サービス拒否(DoS)が発生します。\n' + \
        'ユーザープロファイルのリソース制限を有効にするためには' + \
        'RESOURCE_LIMITパラメータをTRUEに設定する必要があります。'

    refs = {'CIS': 'Recommendation 2.2.13, 2.2.19', 'STIG': 'Rule SV-76305r4'}
#    sat.finding('User Parameters', 'USER.PARAM', summary,
#        severity, details, remarks, refs)
    sat.finding('ユーザーに関する初期化パラメーター'.decode('utf-8'), 'USER.PARAM', summary,
        severity, details, remarks.decode('utf-8'), refs)

def resource_unit(resource, value):
     resource_unit = {'CONNECT_TIME':' minute(s)', 
                      'IDLE_TIME':' minute(s)',
                      'INACTIVE_ACCOUNT_TIME':' day(s)',
                      'PASSWORD_LIFE_TIME':' day(s)',
                      'PASSWORD_GRACE_TIME':' day(s)',
                      'PASSWORD_LOCK_TIME':' day(s)', 
                      'PASSWORD_REUSE_TIME':' day(s)'}
     
     if value in ('UNLIMITED', 'NULL', 'DEFAULT'):
        return ''
     else:
        return resource_unit.get(resource,"")


def user_profiles(profile_dict):
    
    if profile_dict is None:
        sat.diag('Skipped User Profiles')
        return

    rows = []
    for prof, dict in sorted(profile_dict.items()):
        for resource, value in sorted(dict.items()):
            if 'PASSWORD' in resource or 'LOGIN' in resource or \
               resource in ('CONNECT_TIME', 'IDLE_TIME', '(Number of Users)',
                            'INACTIVE_ACCOUNT_TIME'):
                if value == 'DEFAULT':
                    value = profile_dict['DEFAULT'][resource] + \
                            resource_unit(resource,value) + ' (DEFAULT)'
                else:
                    value = value + resource_unit(resource,value)
                rows.append([prof, resource, value])

#    sat.table('User Profiles',
    sat.table('ユーザープロファイル'.decode('utf-8'),
        [['Profile Name', 'Parameter', 'Value']] + rows, header=True)

def user_password(profiles, users):
    if profiles is None:
        sat.diag('Skipped User Password checks')
        return
    severity = sat.SEV_OK
    summary = ''
    details = ''

    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'PASSWORD_LIFE_TIME', ('day', 'days'))
    details += 'PASSWORD_LIFE_TIME:\n'
    details += 'Profiles with limited password lifetime: '+ \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles with unlimited password lifetime: ' + \
               join_list(profile_list) + '\n'
    details += 'Users with unlimited password lifetime: ' + \
               join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = max(severity, sat.SEV_LOW)
        summary += 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' with passwords that never expire. '
    else:
#        summary += 'Password expiration is configured for all users. '
        summary += 'すべてのユーザがパスワードの有効期限が設定されています'.decode('utf-8')

    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'PASSWORD_REUSE_MAX', ('time', 'times'))
    details += '\nPASSWORD_REUSE_MAX:\n'
    details += 'Profiles with limits on password reuse: '+ \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles without limits on password reuse: ' + \
               join_list(profile_list) + '\n'
    details += 'Users without limits on password reuse: ' + \
               join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = max(severity, sat.SEV_LOW)
        summary += 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' with no limits on password reuse. '
    else:
#        summary += 'All users have limits on password reuse. '
        summary += 'すべてのユーザーがパスワード再利用制限が設定されています。'.decode('utf-8')

    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'PASSWORD_REUSE_TIME', ('day', 'days'))
    details += '\nPASSWORD_REUSE_TIME:\n'
    details += 'Profiles with minimum time before password reuse: '+ \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles without minimum time before password reuse: ' + \
               join_list(profile_list) + '\n'
    details += 'Users without minimum time before password reuse: ' + \
               join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = max(severity, sat.SEV_LOW)
        summary += 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' with no minimum time before password reuse. '
    else:
#        summary += 'All users require minimum time before password reuse. '
        summary += 'すべてのユーザーがパスワード再利用可能な時間の制限が設定されています。 '.decode('utf-8')

    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'PASSWORD_GRACE_TIME', ('day', 'days'))
    details += '\nPASSWORD_GRACE_TIME:\n'
    details += 'Profiles with locking after password expiration: '+ \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles without locking after password expiration: ' + \
               join_list(profile_list) + '\n'
    details += 'Users without locking after password expiration: ' + \
               join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = max(severity, sat.SEV_LOW)
        summary += 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' without locking after password expiration.'
    else:
#        summary += 'All user accounts will lock after password expiration.'
        summary += 'すべてのユーザーのアカウントがパスワード失効後にロックされます。'.decode('utf-8')

#    remarks = 'Password expiration is used to ensure that users change ' + \
#        'their passwords on a regular basis. It also provides a mechanism ' + \
#        'to automatically disable temporary accounts. Passwords ' + \
#        'that never expire may remain unchanged for an extended ' + \
#        'period of time. When passwords do not have to be ' + \
#        'changed regularly, users are also more likely to use ' + \
#        'the same passwords for multiple accounts.'
    remarks = 'パスワードの失効はユーザーがパスワードの変更を確実に実施するために利用されます' + \
        'また、自動的に一時的なアカウントを無効にするためのメカニズムを提供します。' + \
		'失効されないパスワードが残っているとパスワードが長期間変更されない可能性があります。' + \
        'パスワードの定期的な変更が必須ではない場合、ユーザーは同じパスワードを複数のアカウントで' + \
        '利用しがちとなります。'

    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommon users cannot be altered in a PDB.\n'
             remarks += '\n一般的なユーザーはPDBで変更できません。\n'

    refs = {'CIS': 'Recommendation 3.3, 3.4, 3.5, 3.6', 
            'STIG': 'Rule SV-76047r2, SV-76051r3, SV-76211r2, SV-76229r2'}

#    sat.finding('Users with Unlimited Password Lifetime', 'USER.NOEXPIRE',
#        summary, severity, details, remarks, refs)
    sat.finding('パスワード有効期限が設定されていないユーザー'.decode('utf-8'), 'USER.NOEXPIRE',
        summary, severity, details, remarks.decode('utf-8'), refs)

def user_login(profiles, users):
    if profiles is None:
        sat.diag('Skipped User Login checks')
        return
    severity = sat.SEV_OK
    summary = ''
    details = ''

    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'FAILED_LOGIN_ATTEMPTS')
    details += 'FAILED_LOGIN_ATTEMPTS:\n'
    details += 'Profiles with limited failed login attempts: '+ \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles with unlimited failed login attempts: ' + \
               join_list(profile_list) + '\n'
    details += 'Users with unlimited failed login attempts: ' + \
               join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = max(severity, sat.SEV_MEDIUM)
        summary += 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' with unlimited failed login attempts. '
    else:
#        summary += 'User accounts are configured to prevent brute force ' + \
#                   'password attacks by locking the account after a number ' +\
#                   'of failed login attempts. '
        summary += 'ブルートフォースパスワード攻撃を防ぐために、何度もログインに失敗するとユーザーアカウントをロックするように設定されています。'.decode('utf-8')

    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'PASSWORD_LOCK_TIME', ('day', 'days'))
    details += '\nPASSWORD_LOCK_TIME:\n'
    details += 'Profiles with minimum lock time: '+ \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles without minimum lock time: ' + \
               join_list(profile_list) + '\n'
    details += 'Users without minimum lock time: ' + \
               join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = max(severity, sat.SEV_LOW)
        summary += 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' without minimum lock time.'
    else:
#        summary +='User accounts are configured to stay locked for a minimum '+\
#                  'duration after being locked due to failed login attempt.'
        summary += 'ユーザーアカウントは、ログイン試行失敗でロックされたら、最小ロック期間が設定されています。'.decode('utf-8')

#    remarks = "Attackers sometimes attempt to guess a user's password " \
#        "by simply trying all possibilities from a set of common " \
#        "passwords. To defend against this attack, it is " \
#        "advisable to use the FAILED_LOGIN_ATTEMPTS and PASSWORD_LOCK_TIME " \
#        "profile resources to lock user accounts for a specified time when " \
#        "there are multiple failed login attempts without a successful " \
#        "login. "
    remarks = '攻撃者はありふれたパスワードのリストの中にユーザのパスワードがないかを試みる推測' + \
        '攻撃を行うことがよくあります。これらの攻撃を防ぐために、ログインの試みが何度か失' + \
        '敗した場合にはユーザーアカウントをロックすることが賢明です。'

    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommon users cannot be altered in a PDB.\n'
             remarks += '\n一般的なユーザーはPDBで変更できません。\n'

    refs = {'CIS': 'Recommendation 3.1, 3.2', 
            'STIG': 'Rule SV-76047r2, SV-76093r2, SV-76095r2, SV-76097r2'}

#    sat.finding('Account Locking after Failed Login Attempts', 'USER.NOLOCK',
#        summary, severity, details, remarks, refs)
    sat.finding('ログイン試行失敗後のアカウントロック'.decode('utf-8'), 'USER.NOLOCK',
        summary, severity, details, remarks.decode('utf-8'), refs)

def password_verify_function(profiles, users):
    profile_list, user_list, exempt_prof_list = \
        profile_unset(profiles, users, 'PASSWORD_VERIFY_FUNCTION')

    if profile_list is None:
        sat.diag('Skipped Password Verification Functions')
        return

    details = 'Profiles with password verification function: ' + \
               join_list(exempt_prof_list) + '\n'
    details += 'Profiles without password verification '+ \
               'function: ' + join_list(profile_list) + '\n'
    details += 'Users without password verification function: ' + \
                   join_list(user_list) + '\n'
    if len(user_list) > 0:
        severity = sat.SEV_MEDIUM
        summary = 'Found ' + sing_plural(len(user_list), 'user', 'users') + \
                  ' not using password verification function.'
    else:
        severity = sat.SEV_OK
#        summary = 'All user accounts are using password verification function.' 
        summary = 'すべてのユーザーアカウントはパスワード認証ファンクションを使用しています。'.decode('utf-8')

#    remarks = 'Password verification functions are used to ensure that ' + \
#        'user passwords meet minimum requirements for ' + \
#        'complexity, which may include factors such as length, ' + \
#        'use of numbers or punctuation characters, difference ' + \
#        'from previous passwords, etc. Oracle supplies several ' + \
#        'predefined functions, or a custom PL/SQL function can ' + \
#        'be used. Every user profile should include a password ' + \
#        'verification function.'
    remarks = 'パスワード検証ファンクションは、ユーザのパスワードが最小限の複雑性(長さ、数字、' + \
        '特殊文字を含んでいるか、以前使用したパスワードと異なるか等）を満たしているかどう' + \
        'かチェックします。Oracle Databaseでそれらの組み合わせを事前定義されたファンクシ' + \
        'ョンまたはユーザ独自のファンクションが使用できます。すべてのユーザプロファイルは' + \
        'このファンクションを含むべきです。'

    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommon users cannot be altered in a PDB.\n'
             remarks += '\n一般的なユーザーはPDBで変更できません。\n'

    refs = {'CIS': 'Recommendation 3.8', 
            'STIG': 'Rule SV-76209r1, SV-76213r1, SV-76215r1 , SV-76217r1, ' + 
                    'SV-76219r1, SV-76221r1, SV-76225r1'}

#    sat.finding('Password Verification Functions', 'USER.PASSWD', summary,
#        severity, details, remarks, refs)
    sat.finding('パスワード検証ファンクション'.decode('utf-8'), 'USER.PASSWD', summary,
        severity, details, remarks.decode('utf-8'), refs)

def get_profile_data():
    profile_data = sat.get_data('profiles', 1)
    if profile_data is None:
        return None

    profile_name = sat.get_index('profiles', 'profile')
    resource = sat.get_index('profiles', 'resource_name')
    limit = sat.get_index('profiles', 'limit')


    profile_dict = {}
    for x in profile_data:
        prof = x[profile_name]
        if prof not in profile_dict:
            profile_dict[prof] = {}
        profile_dict[prof][x[resource]] = x[limit]

    profile_list = list(acct_profiles.values())
    for prof in profile_dict:
        profile_dict[prof]['(Number of Users)'] = \
            str(profile_list.count(prof))

    return profile_dict

def profile_unset(profile_dict, user_profiles, resource_name, units=None):
    matching_profs = []
    nonmatching_profs = []
    for prof in profile_dict.keys():
        value = profile_dict[prof].get(resource_name, 'NULL')
        if value == 'DEFAULT':
            value = profile_dict['DEFAULT'].get(resource_name, 'NULL')
        if value in ('UNLIMITED', 'NULL'):
            matching_profs.append(prof)
        else:
            if units:
                if isinstance(value, int):
                   value = sing_plural(int(value), units[0], units[1])
                else:
                   value = sing_plural(float(value), units[0], units[1])
            nonmatching_profs.append('%s (%s)' % (prof, value))

    user_list = [name for name, prof in user_profiles.items()
                  if prof in matching_profs]

    return sorted(matching_profs), sorted(user_list), sorted(nonmatching_profs) 


def privs_and_roles():
    role_grants = sat.get_data('role_grants', 0)
    system_privs = sat.get_data('system_privs', 0)
    object_privs = sat.get_data('sensitive_obj_privs', 0)
    audit_obj_privs = sat.get_data('audit_obj_privs', 0)
    verifier_privs = sat.get_data('verifier_privs', 0)
    execute_privs = sat.get_data('execute_privs', 1)
    column_privs = sat.get_data('column_privs', 0)
    if role_grants is None or system_privs is None:
        sat.diag('Skipped Privilege and Role checks')
        return

    r_grantee = sat.get_index('role_grants', 'grantee')
    r_role = sat.get_index('role_grants', 'granted_role')
    r_admin = sat.get_index('role_grants', 'is_admin')
    r_common = sat.get_index('role_grants', 'common')
    p_grantee = sat.get_index('system_privs', 'grantee')
    p_priv = sat.get_index('system_privs', 'privilege')
    p_admin = sat.get_index('system_privs', 'is_admin')
    p_common = sat.get_index('system_privs', 'common')
    o_grantee = sat.get_index('sensitive_obj_privs', 'grantee')
    o_priv = sat.get_index('sensitive_obj_privs', 'privilege')
    o_owner = sat.get_index('sensitive_obj_privs', 'owner')
    o_table = sat.get_index('sensitive_obj_privs', 'table_name')
    o_admin = sat.get_index('sensitive_obj_privs', 'is_admin')
    o_common = sat.get_index('sensitive_obj_privs', 'common')
    v_grantee = sat.get_index('verifier_privs', 'grantee')
    v_priv = sat.get_index('verifier_privs', 'privilege')
    v_owner = sat.get_index('verifier_privs', 'owner')
    v_table = sat.get_index('verifier_privs', 'table_name')
    v_admin = sat.get_index('verifier_privs', 'is_admin')
    v_common = sat.get_index('verifier_privs', 'common')
    e_grantee = sat.get_index('execute_privs', 'grantee')
    e_priv = sat.get_index('execute_privs', 'privilege')
    e_package = sat.get_index('execute_privs', 'package')
    e_admin = sat.get_index('execute_privs', 'is_admin')
    e_common = sat.get_index('execute_privs', 'common')
    c_grantee = sat.get_index('column_privs', 'grantee')
    c_priv = sat.get_index('column_privs', 'privilege')
    c_owner = sat.get_index('column_privs', 'owner')
    c_table = sat.get_index('column_privs', 'table_name')
    c_column = sat.get_index('column_privs', 'column_name')
    c_admin = sat.get_index('column_privs', 'is_admin')
    c_common = sat.get_index('column_privs', 'common')
    a_grantee = sat.get_index('audit_obj_privs', 'grantee')
    a_priv = sat.get_index('audit_obj_privs', 'privilege')
    a_owner = sat.get_index('audit_obj_privs', 'owner')
    a_table = sat.get_index('audit_obj_privs', 'table_name')
    a_admin = sat.get_index('audit_obj_privs', 'is_admin')
    a_common = sat.get_index('audit_obj_privs', 'common')

    syspriv_table = [[x[p_grantee], x[p_priv], x[p_admin], 'NO' if p_common == None else x[p_common]] 
                        for x in system_privs]
    role_dict = {}
    for x in role_grants:
        if not (x[r_grantee] == 'PUBLIC' and x[r_role] == 'DV_PUBLIC'):
            role_dict[x[r_grantee]] = role_dict.get(x[r_grantee], []) + \
                [[x[r_role], x[r_admin], 'NO' if r_common == None else x[r_common]]]
#    remarks = 'System privileges provide the ability to access data or ' + \
#        'perform administrative operations for the entire ' + \
#        'database. Consistent with the principle of least ' + \
#        'privilege, these privileges should be granted sparingly. ' + \
#        'The Privilege Analysis feature may be helpful ' + \
#        'to determine the minimum set of privileges required by a ' + \
#        'user or role. In some cases, it may be possible to ' + \
#        'substitute a more limited object privilege grant in ' + \
#        'place of a system privilege grant that applies to all ' + \
#        'objects. System privileges should be granted with admin ' + \
#        'option only when the recipient needs the ability to ' + \
#        'grant the privilege to others.'
    remarks = 'システム権限は、データへのアクセスやデータベース全体に対して管理操作を実行する権' + \
        '限として提供されます。最小権限の原則に従って、システム権限は慎重に付与しなければ' + \
        'なりません。どの権限が不必要か判断つかない時、Privilege Analysis機能が、ユーザやロールが必要' + \
        'とする最小の権限を洗い出すのに役立ちます。場合によっては、すべてのオブジェクトを対' + \
        '象に付与されているシステム権限が、より制限されたオブジェクト権限に置き換えること' + \
        'が可能かもしれません。また、システム権限の受領者がその権限を別に付与する必要があるとき' + \
        'は、システム権限はWITH ADMINオプションで付与しておく必要があります。'

    refs = {'CIS': 'Recommendation 4.7', 
            'STIG': 'Rule SV-75923r3, SV-76065r1, SV-76081r3, SV-76299r3'}
    priv_list = [x[p_priv] for x in system_privs]
    priv_list = sorted(list(set(priv_list)))
    details = 'Users directly or indirectly granted each system privilege:\n\n'
    num_total = 0
    num_admin = 0
    num_direct = 0
    num_unique = 0
    unique_users_all_privs = []
    unique_users_with_admin = []
    unique_users_directly_granted = []
    for priv in priv_list:
        users, unique_users, admin, unique_admin_grantees, direct, unique_direct_grantees = get_sys_priv_grantees(priv, True)
        if len(users) > 0:
           details += '%s: %s\n' % (priv, join_list(users))
        num_total += len(users)
        num_admin += admin
        num_direct += direct
        unique_users_all_privs = unique_users_all_privs + list(set(unique_users) - set(unique_users_all_privs))
        unique_users_with_admin = unique_users_with_admin + list(set(unique_admin_grantees) - set(unique_users_with_admin))
        unique_users_directly_granted = unique_users_directly_granted + list(set(unique_direct_grantees) - set(unique_users_directly_granted))
    if num_admin > 0:
        details += '\n(*) = granted with admin option'
        details += '\n(D) = granted directly'
        details += '\n(C) = granted commonly'
    severity, summary = grant_summary('system privileges', 'admin', 
        num_total, num_admin,len(acct_profiles), len(unique_users_all_privs), len(unique_users_with_admin), len(unique_users_directly_granted))
    if num_direct > 0:
        if len(unique_users_directly_granted) == 1:
            summary += ' 1 user is granted %d system privileges directly.\n' % (num_direct)
        else:
            summary += ' %d users are granted %d system privileges directly.\n' % (len(unique_users_directly_granted), num_direct)

    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted system privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与されたシステム権限は、PDBで取り消すことはできません。\n'

#    sat.finding('System Privilege Grants', 'PRIV.SYSTEM', summary,
#        severity, details, remarks, refs)
    sat.finding('すべてのシステム権限'.decode('utf-8'), 'PRIV.SYSTEM', summary,
        severity, details, remarks.decode('utf-8'), refs)

    roles_unique_users = []
    if con_type == 'PDB':
       role_list = [x[r_role] for x in role_grants if x[r_common] == 'NO']
    else:
        role_list = [x[r_role] for x in role_grants]
    role_list = sorted(list(set(role_list)))
    details = 'Users directly or indirectly granted each role:\n\n'
    num_total = 0
    for role in role_list:
        if con_type == 'PDB':
           users = get_local_role_grantees(role, role_grants, r_grantee, r_role, r_common)
        else:
           users = get_role_grantees(role, role_grants, r_grantee, r_role)
        roles_unique_users = roles_unique_users + list(set(users) - set(roles_unique_users))
        if len(users) > 0:
          details += '%s: %s\n' % (role, join_list(users))
        num_total += len(users)
    severity, summary = grant_summary('roles', 'admin', num_total, 0, len(acct_profiles), len(roles_unique_users),0, 0)
#    remarks = 'Roles are a convenient way to manage groups of related ' + \
#        'privileges, especially when the privileges are required ' + \
#        'for a particular task or job function. Beware of ' + \
#        'broadly defined roles, which may confer more privileges ' + \
#        'than an individual recipient requires. Privilege Analysis can ' + \
#        'be used to determine specific privileges that the recipient actually requires. ' + \
#        'Roles should be granted with admin option only when the recipient needs ' + \
#        'the ability to modify the role or grant it to others. ' 
    remarks = 'ロールは、特定のタスクやジョブ機能に権限が要求される場合、関連する権限をグループ' + \
        'として管理できる便利な方法です。個々の受領者が要求しているよりも多くの権限が参照' + \
        'されてるような広範囲なロールの場合は、特に注意をして下さい。' + \
        '権限分析は、受領者が実際に必要とする特定の権限を決定するために使用することができます。' + \
        '受領者がロールを変更したり、そのロールを別に付与するような権限が必要な場合は、ロ' + \
        'ールにadminオプションで付与しておく必要があります。'

    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted roles cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与されたロールをPDBで取り消すことはできません。\n'
    refs = {'CIS': 'Recommendation 4.4.1'}
#    sat.finding('All Roles', 'PRIV.ROLES', summary,
#        severity, details, remarks, refs)
    sat.finding('すべてのロール'.decode('utf-8'), 'PRIV.ROLES', summary,
        severity, details, remarks.decode('utf-8'), refs)

        
    cbac_role_grants = sat.get_data('cbac_role_grants',1)
    if cbac_role_grants is None:
       sat.diag('Skipped CBAC Role checks')
       return
    cbac_user_privs = sat.get_data('cbac_user_privs',1)

    cbac_owner = sat.get_index('cbac_role_grants', 'owner')
    cbac_name = sat.get_index('cbac_role_grants', 'procedure')
    cbac_type = sat.get_index('cbac_role_grants', 'type')
    cbac_granted_role = sat.get_index('cbac_role_grants', 'role')
    priv_cbac_owner = sat.get_index('cbac_user_privs', 'owner')
    priv_cbac_grantee = sat.get_index('cbac_user_privs', 'grantee')
    priv_cbac_name = sat.get_index('cbac_user_privs', 'table_name')

    cbac_dict = {}
    cbac_role_privs = {}
    cbac_users = {}
    cbac_to_pub = False

    for x in cbac_role_grants:
       str = x[cbac_owner] + '.' + x[cbac_name]
       cbac_dict[x[cbac_owner] + '.' + x[cbac_name]] = \
                      cbac_dict.get(x[cbac_owner] + '.' + x[cbac_name], []) + \
                                   [x[cbac_granted_role]]
       cbacprivs = []
       for y in system_privs:
           if y[p_grantee] == x[cbac_granted_role]:
              cbacprivs.append(y[p_priv])

       cbac_role_privs[x[cbac_owner] + '.' + x[cbac_name]] = \
                 cbac_role_privs.get(x[cbac_owner] + '.' + x[cbac_name],[]) + \
                                      cbacprivs
       cbacusers = []
       for z in cbac_user_privs:
           if z[priv_cbac_owner] + '.' + z[priv_cbac_name] == \
                                            x[cbac_owner] + '.' + x[cbac_name]:
              if z[priv_cbac_grantee] == 'PUBLIC':
                       cbac_to_pub = True                       
              if z[priv_cbac_grantee] in all_roles:
                   if con_type == 'PDB':
                       for cu in get_local_role_grantees( z[priv_cbac_grantee], 
                                 role_grants, r_grantee, r_role, r_common):
                           cbacusers.append(cu)
                   else:
                       for cu in get_role_grantees( z[priv_cbac_grantee], 
                                 role_grants, r_grantee, r_role):
                           cbacusers.append(cu)
              else:
                  cbacusers.append(z[priv_cbac_grantee])
       cbac_users[x[cbac_owner] + '.' + x[cbac_name]] = \
                     cbac_users.get(x[cbac_owner] + '.' + x[cbac_name], []) + \
                                                 cbacusers
    severity = sat.SEV_UNKNOWN
    summary = ''
    details = ''
    if len(cbac_dict) > 0:
       summary += 'Code Based Access Control (CBAC) enabled for ' + \
                  '%d Program Units.\n' % len(cbac_dict)
       details += 'Following Program Units are granted CBAC Roles:\n\n'
       for a in cbac_dict:
           details += a + ': ' + ', '.join(cbac_dict[a]) + '\n'
           if len(cbac_role_privs[a]) > 0:
              details += 'Privileges granted via CBAC role: ' + \
                        ', '.join(cbac_role_privs[a]) + '\n'
           if len(cbac_users[a]) > 0:
              details += 'Users with execute privilege: ' + \
                         ', '.join(cbac_users[a]) + '\n\n'
       if cbac_to_pub == True:
          details += 'PUBLIC is granted Execute on Program Units via CBAC Role.\n'
          severity = sat.SEV_MEDIUM
    else:
       summary += 'Code Based Access Control (CBAC) not used for any ' + \
                  'Program Units. \n'

#    remarks = 'Code Based Access Control (CBAC) can be used to grant ' + \
#              'additional privileges on program units like PL/SQL functions, '+\
#              'procedures, or packages. CBAC allows you to ' + \
#              'attach database roles to a PL/SQL function, procedure, or ' + \
#              'package. These database roles are enabled at run time, ' + \
#              'enabling the program unit to execute with the required ' + \
#              'privileges in the calling user\'s environment.'
    remarks = 'コードベースのアクセス制御（CBAC）を使用して、PL/SQL関数、プロシージャ、' + \
              'パッケージなどのプログラムユニットに追加の権限を付与できます。'+ \
              'CBACを使用すると、データベースロールをPL/SQL関数、プロシージャ、' + \
              'またはパッケージに添付できます。これらのデータベースロールは、' + \
              '実行時に有効になり、プログラムユニットが呼び出し元ユーザーの環境で' + \
              '必要な権限で実行できるようにします。'

#    sat.finding('Code Based Access Control', 'PRIV.CBAC',
#        summary, severity, details, remarks)
    sat.finding('コードベースのアクセス制御'.decode('utf-8'), 'PRIV.CBAC',
        summary, severity, details, remarks.decode('utf-8'))


    priv_list = ['ALTER USER', 'CREATE USER', 'DROP USER']
    privs, heading = filter_system_privs(syspriv_table, priv_list)
    desc= 'account management privileges'
#    remarks = 'Account management privileges ' + \
#              '(' + join_list(priv_list) + ') ' + \
#              'can be used to create and modify other user accounts, ' + \
#              'including changing passwords. This ability can be abused to ' + \
#              'gain access to another user\'s account, which may have ' + \
#              'greater privileges. Users with Account management privileges ' + \
#              'should be audited.'
    remarks = 'ユーザーアカウントの管理権限(ALTER USER, CREATE USER, DROP USER)は、' + \
        'ユーザ作成や変更、パスワードの変更等で使用されます。' + \
        'これはより強い権限を持つ他のユーザーアカウントを乱用' + \
        'することができてしまう可能性があるので、注意が必要です。' + \
		'ユーザーアカウント管理権限を持つユーザーを監査する必要があります。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted account management ' + \
#                        'privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与されたアカウント管理権限は、PDBで取り消すことはできません。\n'


    refs = {'STIG': 'Rule SV-75935r2' }
    severity, summary, details = \
        priv_grant_details(privs, role_dict, 'admin', heading, desc)
#    sat.finding('Account Management Privileges', 'PRIV.ACCT',
#        summary, severity, details, remarks, refs)
    sat.finding('アカウント管理権限'.decode('utf-8'), 'PRIV.ACCT',
        summary, severity, details, remarks.decode('utf-8'), refs)

    priv_list = ['ALTER ANY ROLE', 'CREATE ROLE', 'DROP ANY ROLE', 
                 'GRANT ANY OBJECT PRIVILEGE', 
                 'GRANT ANY PRIVILEGE', 'GRANT ANY ROLE']
    privs, heading = filter_system_privs(syspriv_table, priv_list)
    desc= 'role and privilege management privileges'
#    remarks = 'Users with role and privilege management privileges ' + \
#        '(' + join_list(priv_list) + ') ' + \
#        'can change the set of roles and ' + \
#        'privileges granted to themselves and other users. This ability ' + \
#        'should be granted sparingly, since it can be used to circumvent ' + \
#        'many security controls in the database. ' + \
#        'The Privilege Analysis feature may be helpful to determine whether ' + \
#        'a user or role have used privilege management privileges.'
    remarks = 'ユーザのシステム権限(ALTER ANY ROLE, CREATE ROLE, DROP ANY ROLE, GRANT ANY OBJEC' + \
        'T PRIVILEGE, GRANT ANY PRIVILEGE, GRANT ANY ROLE)は、ロールや権限セットの内容を変更する' + \
        'ことや他のユーザへ付与することができます。これはデータベースにある多くのセキュリ' + \
        'ティ制御を迂回するために使うことができるので、慎重に付与する必要があります。' + \
		'Privilege Analysis機能は、ユーザーまたはロールが権限セットを管理する権限を使用しているかどうかを判断するのに役立ちます。'

    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted role and privilege management ' + \
#                        'privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与されたロールおよび権限管理権限は、PDBで取り消すことはできません。\n'

    refs = {'CIS': 'Recommendation 4.3.10, 4.3.11, 4.3.12'}
    severity, summary, details = \
        priv_grant_details(privs, role_dict, 'admin', heading, desc)
#    sat.finding('Role and Privilege Management Privileges', 'PRIV.MGMT',
#        summary, severity, details, remarks, refs)
    sat.finding('ロールおよび権限管理権限'.decode('utf-8'), 'PRIV.MGMT',
        summary, severity, details, remarks.decode('utf-8'), refs)

    priv_list = ['ALTER DATABASE', 'ALTER SYSTEM', 'CREATE ANY LIBRARY',
        'CREATE LIBRARY', 'DROP ANY LIBRARY']
    privs, heading = filter_system_privs(syspriv_table, priv_list)
    desc= 'database management privilege'
#    remarks = 'Database management privileges ' + \
#        '(' + join_list(priv_list) + ') ' + \
#        'can be used to change the operation of the database ' + \
#        'and potentially bypass security protections. CREATE LIBRARY allows '+\
#        'a user to create or replace a library. ' + \
#        'This ability should be granted only to trusted administrators and ' + \
#        'should be sufficiently audited.' 
    remarks = 'データベースの管理権限(ALTER DATABASE, ALTER SYSTEM, CREATE ANY LIBRARY, CREATE LIBRARY, ' + \
        'DROP ANY LIBRARY)は、データベースの操作を変更し、セキュリティ保護を回避することができます。' + \
        'CREATE LIBRARYを使用すると、ユーザーはライブラリを作成または置換できます。' + \
        'これは信頼できる管理者にのみ付与し、十分に監査する必要があります。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted Database management ' + \
#                        'privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与されたデータベース管理権限は、PDBで取り消すことはできません。\n'


    refs = {'CIS': 'Recommendation 4.3.7, 4.3.8, 4.3.9'}
    severity, summary, details = \
        priv_grant_details(privs, role_dict, 'admin', heading, desc)
#    sat.finding('Database Management Privileges', 'PRIV.DBMGMT',
#        summary, severity, details, remarks, refs)
    sat.finding('データベース管理権限'.decode('utf-8'), 'PRIV.DBMGMT',
        summary, severity, details, remarks.decode('utf-8'), refs)

    if execute_privs is None:
        sat.diag('Skipped Execute DBMS_AUDIT_MGMT check')
    else:
        pkgs = ['DBMS_AUDIT_MGMT']
        priv_grants = [[x[e_grantee],
             x[e_priv]+' on '+x[e_package],
             x[e_admin], 'NO' if e_common == None else x[e_common]] for x in execute_privs if x[e_package] in pkgs]
        heading = 'Grants of EXECUTE on ' + join_list(pkgs)
        desc = 'EXECUTE on Audit management packages'
        pkg_severity, pkg_summary, details = \
            priv_grant_details(priv_grants, role_dict, 'grant', heading, desc)
        severity = pkg_severity
        summary = pkg_summary
#        remarks = 'The DBMS_AUDIT_MGMT package is used to execute ' + \
#            'Audit Trail management procedures and functions. ' + \
#            'Users with the execute privilege can invoke subprograms ' + \
#            'like CLEAN_AUDIT_TRAIL that deletes audit trail records ' + \
#            'or files that have been archived. ' + \
#            'Access should be strictly limited and ' + \
#            'granted only to users with a legitimate need for this ' + \
#            'functionality.' 
        remarks = 'DBMS_AUDIT_MGMTパッケージは、監査証跡管理手順および機能を実行するために使用されます。' + \
            '実行権限を持つユーザーは、監査証跡レコードまたはアーカイブされたファイルを削除する' + \
            'CLEAN_AUDIT_TRAILなどのサブプログラムを起動できます。' + \
            'アクセスは厳密に制限され、この機能を正当に必要としているユーザーにのみ付与されるべきです。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted EXECUTE on Audit management ' + \
#                        'packages cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与された監査管理パッケージの実行権限は、PDBで取り消すことはできません。\n'

        refs = {'STIG': 'SV-76149r1, SV-76151r1, SV-76153r1'}
#        sat.finding('Audit Management Package', 'PRIV.AUDMGMT',
#            summary, severity, details, remarks, refs) 
        sat.finding('監査管理パッケージ'.decode('utf-8'), 'PRIV.AUDMGMT',
            summary, severity, details, remarks.decode('utf-8'), refs)

    priv_list = ['AUDIT ANY', 'AUDIT SYSTEM']
    privs, heading = filter_system_privs(syspriv_table, priv_list)
    desc= 'privilege to manage audit policies'
#    remarks = 'Audit management privileges ' + \
#        '(' + join_list(priv_list) + ') ' + \
#        'can be used to add, drop and modify the audit policies ' + \
#        'for the database. This ability should be granted sparingly, ' + \
#        'since it may be used to hide malicious activity. ' + \
#        'The Privilege Analysis feature may be helpful to determine ' + \
#        'whether the audit management privileges have been used by ' + \
#        'a user or role. Users with these privileges should be ' + \
#        'sufficiently audited.'
    remarks = '監査の管理権限(AUDIT ANY, AUDIT SYSTEM)は、データベースの' + \
        '監査ポリシーを追加、削除、変更するために使用されます。' + \
        'これは不正なアクティビティを隠すために使用される危険性があるので慎重に付与する必要があります。' + \
		'Privilege Analysis機能は、ユーザーまたはロールが監査管理権限を使用したかどうかを判断するのに役立ちます。' + \
		'これらの権限を持つユーザーは十分に監査する必要があります。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted Audit management ' + \
#                        'privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与された監査管理権限は、PDBで取り消すことはできません。\n'
    refs = {'CIS': 'Recommendation 4.3.3', 
            'STIG': 'Rule SV-76113r1'}
    severity, summary, details = \
        priv_grant_details(privs, role_dict, 'admin', heading, desc)
#    sat.finding('Audit Management Privileges', 'PRIV.AUDIT',
#        summary, severity, details, remarks, refs)
    sat.finding('監査管理権限'.decode('utf-8'), 'PRIV.AUDIT',
        summary, severity, details, remarks.decode('utf-8'), refs)

    priv_list = ['SELECT ANY TABLE', 'READ ANY TABLE', 'INSERT ANY TABLE',
                 'DELETE ANY TABLE', 'ALTER ANY TABLE', 'UPDATE ANY TABLE',
                 'CREATE ANY TRIGGER', 'ALTER ANY TRIGGER', 'CREATE ANY INDEX',
                 'CREATE ANY PROCEDURE', 'SELECT ANY DICTIONARY']
    privs, heading = filter_system_privs(syspriv_table, priv_list)
    desc= 'broad data access privileges'
#    remarks = 'Users with broad data access privileges ' + \
#        '(' + join_list(priv_list) + ') ' + \
#        'have very broad access to data stored in any schema. ' + \
#        'Most administrative tasks do not ' + \
#        'require access to the data itself, so these privileges ' + \
#        'should be granted rarely even to administrators. ' + \
#        'Users with direct object privileges on tables that holds sensitive '+ \
#        'data should also be reviewed. ' + \
#        'In addition to minimizing grants of these privileges, ' + \
#        'consider the use of Database Vault realms to limit the ' + \
#        'use of these privileges to access sensitive data stored in user schemas.\n' + \
#        'Also, the Privilege Analysis feature may be helpful to ' + \
#        'restrict the use of broad data access privileges required by a user or ' + \
#        'role. In some cases, it may be possible to substitute a more ' + \
#        'limited object privilege grant in place of a system privilege grant ' + \
#        'that applies to all objects. System privileges should be granted ' + \
#        'with admin option only when the recipient needs the ability to grant ' + \
#        'the privilege to others.'
    remarks = 'ユーザの幅広いデータアクセス権限 (SELECT ANY TABLE, READ ANY TABLE, INSERT ANY TABLE, ' + \
        'DELETE ANY TABLE, ALTER ANY TABLE, UPDATE ANY TABLE, CREATE ANY TRIGGER, ALTER ANY TRIGGER, ' + \
        'CREATE ANY INDEX, CREATE ANY PROCEDURE, SELECT ANY DICTIONARY)は、任意のスキーマに' + \
        '対する広範なアクセスができます。多くの管理タスクはデータ自身へ' + \
        'のアクセスは必要としないので、これらの権限は管理者へ付与されることは稀です。' + \
		'機密情報を保持しているテーブルに対する直接のオブジェクト権限を持つユーザーも確認する必要があります。' + \
        'これらの権限を最小限にするために、ユーザスキーマに格納する機密情報へのアクセスする権限を制限する' + \
        'ためにDatabase Vaultのレルムを検討することも有効な手段です。\n' + \
		'また、Privilege Analysis機能は、ユーザーまたはロールに必要な幅広いデータアクセス権限の使用を制限するのに役立ちます。' + \
		'場合によっては、すべてのオブジェクトに適用されるシステム権限付与の代わりに、' + \
		'より限定されたオブジェクト権限付与を代用することも可能です。' + \
		'権限の受取人が他のユーザーに権限を付与する機能を必要とする場合にのみ、' + \
		'システム権限をwith adminオプションで付与するべきです。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted broad data access ' + \
#                        'privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与された幅広いデータアクセス権限は、PDBで取り消すことはできません。\n'
    refs = {'CIS': 'Recommendation 4.3.1, 4.3.2'}
    severity, summary, details = \
        priv_grant_details(privs, role_dict, 'admin', heading, desc)
#    sat.finding('Broad Data Access Privileges', 'PRIV.DATA',
#        summary, severity, details, remarks, refs)
    sat.finding('幅広いデータアクセス権限'.decode('utf-8'), 'PRIV.DATA',
        summary, severity, details, remarks.decode('utf-8'), refs)

    priv_list = ['EXEMPT ACCESS POLICY', 'EXEMPT REDACTION POLICY']
    privs, heading = filter_system_privs(syspriv_table, priv_list)
    desc= 'access control exemption privileges'
#    remarks = 'Users with access control exemption privileges ' + \
#        '(' + join_list(priv_list) + ') ' + \
#        'can bypass the row and column access control ' + \
#        'policies enforced by Virtual Private Database and ' + \
#        'Data Redaction, respectively. Most administrative tasks do not ' + \
#        'require access to the data itself, so these privileges should be ' + \
#        'granted rarely even to administrators. ' + \
#        'Users with these privileges should be sufficiently audited.'
    remarks = 'アクセス制御免除権限を持つユーザ(EXEMPT ACCESS POLICY, EXEMPT REDACTION POLICY)は、Virtual ' + \
        'Private DatabaseやData Redactionで構成された行と列のアクセス制御ポリシーをそれぞれにバイパスすることができ' + \
        'ます。多くの管理タスクはデータ自身へのアクセスは必要としないので、これらの権限は' + \
        '管理者へ付与されることは稀です。' + \
		'これらの権限を持つユーザーは十分に監査する必要があります。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#             remarks += '\nCommonly granted access control exemption ' + \
#                        'privileges cannot be revoked in a PDB.\n'
             remarks += '\n一般に付与されたアクセス制御免除権限は、PDBで取り消すことはできません。\n'
    refs = {'CIS': 'Recommendation 4.3.4'}
    severity, summary, details = \
        priv_grant_details(privs, role_dict, 'admin', heading, desc)
#    sat.finding('Access Control Exemption Privileges', 'PRIV.EXEMPT',
#        summary, severity, details, remarks, refs)
    sat.finding('アクセス制御が免除される権限'.decode('utf-8'), 'PRIV.EXEMPT',
        summary, severity, details, remarks.decode('utf-8'), refs)

    if verifier_privs is None:
        sat.diag('Skipped Access to Password Verifier checks')
    else:
        priv_grants = [[x[v_grantee],
             x[v_priv]+' on '+x[v_owner]+'.'+x[v_table],
             x[v_admin], 'NO' if v_common == None else x[v_common]] for x in verifier_privs]
        heading = 'Grants of READ, SELECT on objects containing verifiers'
        desc = 'read on dictionary tables containing password verifiers'
        severity, summary, details = \
            priv_grant_details(priv_grants, role_dict, 'grant', heading, desc)
#        remarks = 'Users with READ, SELECT and UPDATE privileges on dictionary ' + \
#            'tables containing verifiers can access and modify ' + \
#            'user password verifiers. ' + \
#            'The verifiers can be used in offline attacks to discover ' + \
#            'user passwords.'
        remarks = '認証情報を含むディクショナリテーブルに対するREAD、SELECT、およびUPDATE権限を持つユーザーは、' + \
            'ユーザーパスワード認証情報にアクセスして変更できます。' + \
            'この認証情報はユーザのパスワードを発見するオフライン攻撃に使用されます。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#            remarks += '\nCommonly granted read, select and update ' + \
#                       'privileges on dictionary tables containing ' + \
#                       'verifiers cannot be revoked in a PDB.\n'
            remarks += '\n一般的に付与された認証情報を含むディクショナリテーブルに対するREAD、SELECT、およびUPDATE権限は、PDBで取り消すことはできません。\n'

        refs = {'CIS': 'Recommendation 4.5.1, 4.5.2, 4.5.3, 4.5.4, 4.5.6'}
#        sat.finding('Access to Password Verifier Tables', 'PRIV.PASSWD',
#            summary, severity, details, remarks, refs)
        sat.finding('認証情報格納表へのアクセス'.decode('utf-8'), 'PRIV.PASSWD',
            summary, severity, details, remarks.decode('utf-8'), refs)

    if object_privs is None:
        sat.diag('Skipped Write Access to Restricted Object checks')
    else:
        priv_grants = [[x[o_grantee],
             x[o_priv]+' on '+x[o_owner]+'.'+x[o_table],
             x[o_admin], 'NO' if o_common == None else x[o_common]] for x in object_privs]
        heading = 'Grants of DELETE, INSERT, UPDATE on ' + \
            'SYS, DVSYS, AUDSYS or LBACSYS objects'
        desc = 'object privileges on Oracle Database restricted objects'
        severity, summary, details = \
            priv_grant_details(priv_grants, role_dict, 'grant', heading, desc)
#        remarks = 'Users with these privileges can directly modify objects ' + \
#            'in the SYS, DVSYS, AUDSYS or LBACSYS schemas. Manipulating ' + \
#            'these system objects may allow security protections to be ' + \
#            'circumvented or otherwise interfere with normal ' + \
#            'operation of the database. ' + \
#            'PUBLIC must not be granted access to objects in SYS, ' + \
#            'DVSYS, AUDSYS and LBACSYS schemas. ' + \
#            'When running a Privilege Analysis Capture, be aware of privileges ' + \
#            'that have been granted to access objects in any Oracle-created ' + \
#            'schemas. Review the grants for relevance.'
        remarks = 'これらの権限を持つユーザは、SYS, DVSYS, AUDSYS, or LBACSYSスキーマのオブジェクトを変更す' + \
            'ることができます。システムオブジェクトを操作することは、セキュリティ保護' + \
            'を迂回することやデータベースの通常の運用を阻害することになりえます。' + \
			'SYS、DVSYS、AUDSYSおよびLBACSYSスキーマのオブジェクトに対して、' + \
			'PUBLICにはオブジェクトへのアクセスを許可しないでください。' + \
			'Privilege Analysis Captureを実行するときは、' + \
			'Oracleが作成したスキーマ内のオブジェクトにアクセスするために付与されている権限に注意してください。' + \
			'権限付与の妥当性を確認してください。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#            remarks += '\nCommonly granted write ' + \
#                       'privileges on SYS, DVSYS, AUDSYS or LBACSYS objects ' + \
#                       'cannot be revoked in a PDB.\n'
            remarks += '\n一般にSYS、DVSYS、AUDSYSまたはLBACSYSオブジェクトに対する付与された書込み権限は、PDBで取り消すことはできません。\n'

        refs = {'STIG': 'Rule SV-75929r3' }
#        sat.finding('Write Access to Restricted Objects', 'PRIV.OBJ',
#            summary, severity, details, remarks, refs)
        sat.finding('制限されたオブジェクトへの書込みアクセス'.decode('utf-8'), 'PRIV.OBJ',
            summary, severity, details, remarks.decode('utf-8'), refs)

    if audit_obj_privs is None:
        sat.diag('Skipped Access to Audit Object checks')
    else: 
        priv_grants = [[x[a_grantee],
             x[a_priv]+' on '+x[a_owner]+'.'+x[a_table],
             x[a_admin], 'NO' if a_common == None else x[a_common]] for x in audit_obj_privs]
        heading = 'Grants of SELECT, DELETE, INSERT, UPDATE on ' + \
            'AUDIT objects'
        desc = 'object privileges on audit objects'
        severity, summary, details = \
            priv_grant_details(priv_grants, role_dict, 'grant', heading, desc)
#        remarks = 'Users with these privileges can directly access and ' + \
#            'modify objects containing audit information. Access to these ' + \
#            'objects may allow a malicious user deduce privilege settings ' + \
#            'for other users and to manipulate the audit information ' + \
#            'by replacing or deleting audit records.\n' + \
#            'Use Privilege Analysis to identify used and unused access to ' + \
#            'these privileges. Instead of granting a default role with ' + \
#            'many privileges such as DBA or SELECT_CATALOG_ROLE, ' + \
#            'create custom roles that only contain the ' + \
#            'necessary system and object privileges the user or role needs ' + \
#            'to perform the task.'
        remarks = 'これらの権限を持つユーザーは、監査情報を含むオブジェクトに直接アクセスして変更することができます。' + \
            'これらのオブジェクトにアクセスすると、悪意のあるユーザーが他のユーザーの権限設定を推測したり、' + \
            '監査レコードを置き換えたり削除したりして監査情報を操作する可能性があります。\n' + \
            'Privilege Analysisを使用して、これらの権限に対する使用済および未使用のアクセスを識別します。' + \
            'DBAやSELECT_CATALOG_ROLEなどの多数の権限を持つデフォルトのロールを付与する代わりに、ユーザーまたは' + \
            'ロールがタスクを実行するために必要なシステムおよびオブジェクト権限のみを含むカスタムロールを作成してください。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#            remarks += '\nCommonly granted object ' + \
#                       'privileges on audit objects cannot be revoked in a PDB.\n'
            remarks += '\n一般に付与された監査オブジェクトに関するオブジェクト権限は、PDBで取り消すことはできません。\n'

        refs = {'STIG': 'Rule SV-76143r2, SV-76145r1, SV-76147r1, SV-76159r1'}
#        sat.finding('Access to Audit Objects', 'PRIV.AUDOBJ',
#            summary, severity, details, remarks, refs)
        sat.finding('監査オブジェクトへのアクセス'.decode('utf-8'), 'PRIV.AUDOBJ',
            summary, severity, details, remarks.decode('utf-8'), refs)

    if execute_privs is None:
        sat.diag('Skipped Execute Privilege checks')
    else: 
        priv_list = ['BECOME USER']
        privs, heading = filter_system_privs(syspriv_table, priv_list)
        desc= 'user impersonation privilege'
        severity, summary, details = \
            priv_grant_details(privs, role_dict, 'admin', heading, desc)
        pkgs = ['DBMS_AQADM_SYS', 'DBMS_AQADM_SYSCALLS', 
            'DBMS_IJOB', 'DBMS_PRVTAQIM', 'DBMS_REPCAT_SQL_UTL',
            'DBMS_SCHEDULER', 'DBMS_STREAMS_ADM_UTL', 'DBMS_STREAMS_RPC',
            'DBMS_SYS_SQL', 'INITJVMAUX', 'LTADM',
            'WWV_DBMS_SQL', 'WWV_EXECUTE_IMMEDIATE']
        priv_grants = [[x[e_grantee],
             x[e_priv]+' on '+x[e_package],
             x[e_admin], 'NO' if e_common == None else x[e_common]] for x in execute_privs if x[e_package] in pkgs]
        heading = 'Grants of EXECUTE on ' + join_list(pkgs)
        desc = 'EXECUTE on restricted packages that can be executed with ' + \
               'the identity of some other user'
        pkg_severity, pkg_summary, pkg_details = \
            priv_grant_details(priv_grants, role_dict, 'grant', heading, desc)
        severity = max(severity, pkg_severity)
        summary += ' ' + pkg_summary
        if pkg_details:
            details += '\n' + pkg_details
#        remarks = 'The BECOME USER privilege and some PL/SQL packages ' + \
#            '(' + join_list(pkgs) + ') ' + \
#            'allow for execution of SQL code ' + \
#            'or external jobs using the identity of a different user. ' + \
#            'Access should be strictly limited and ' + \
#            'granted only to users with a legitimate need for this ' + \
#            'functionality. Use Privilege Analysis to identify used and ' + \
#            'unused access to these privileges. Users with BECOME USER ' + \
#            'privilege and EXECUTE privilege on above packages should be ' + \
#            'sufficiently audited.'
        remarks = 'BECOME USER権限とPL/SQLパッケージ(DBMS_AQADM_SYS、DBMS_AQADM_SYSCALLS、' + \
            'DBMS_IJOB、DBMS_PRVTAQIM、DBMS_REPCAT_SQL_UTL、DBMS_SCHEDULER、DBMS_STREAMS_ADM_UTL、' + \
            'DBMS_STREAMS_RPC、DBMS_SYS_SQL、INITJVMAUX、LTADM、WWV_DBMS_SQL、WWV_EXECUTE_IMMEDIATE)は、' + \
            '別のユーザの識別情報を使ってSQLコードや外部ジョブを実行することを許可します。' + \
            'このアクセス権限は厳しく制限し、正当に必要なユーザにのみ付与すべきです。' + \
			'Privilege Analysisを使用して、これらの権限に対する使用済および未使用のアクセスを識別します。' + \
			'上記のパッケージに対するBECOME USER権限とEXECUTE権限を持つユーザーは、十分に監査する必要があります。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#            remarks += '\nCommonly granted BECOME USER ' + \
#                       'privilege cannot be revoked in a PDB.\n'
            remarks += '\n一般に付与されたBECOME USER権限は、PDBで取り消すことはできません。\n'
        refs = {'CIS': 'Recommendation 4.1.10, 4.2.1, 4.2.3 - 4.2.13, 4.3.5'}
#        sat.finding('User Impersonation Privilege', 'PRIV.USER',
#            summary, severity, details, remarks, refs)
        sat.finding('ユーザのなりすまし権限'.decode('utf-8'), 'PRIV.USER',
            summary, severity, details, remarks.decode('utf-8'), refs)

        pkgs = ['DBMS_BACKUP_RESTORE', 'UTL_DBWS', 'UTL_ORAMTS'] 
        priv_grants = [[x[e_grantee],
             x[e_priv]+' on '+x[e_package],
             x[e_admin], 'NO' if e_common == None else x[e_common]] for x in execute_privs if x[e_package] in pkgs]
        heading = 'Grants of EXECUTE on ' + join_list(pkgs)
        desc = 'EXECUTE on restricted packages that can be used for data ' + \
               'exfiltration. '
        severity, summary, details = \
            priv_grant_details(priv_grants, role_dict, 'grant', heading, desc)
        if summary == NO_USER_GRANTED + desc:
             summary = 'No User is granted Execute on restricted PL/SQL ' + \
                       'packages that can be used for data exfiltration'
#        remarks = 'Some PL/SQL packages ' + \
#            '(' + join_list(pkgs) + ') ' + \
#            'can send data from the ' + \
#            'database using the network or file system. Access should be ' + \
#            'granted only to users with a legitimate need for this ' + \
#            'functionality. Use Privilege Analysis to identify if these ' + \
#            'privileges were used. If not, consider revoking.'
        remarks = 'PL/SQLパッケージ(DBMS_BACKUP_RESTORE、UTL_DBWS、UTL_ORAMTS)は、ネットワークやファイルシステム' + \
            'を使ってデータベースからデータを送信することができます。この機能が正当に必要なユーザにのみ付与すべきです。' + \
            'Privilege Analysisを使用して、これらの権限が使用されるかを識別します。' + \
			'使用されない場合、これらの権限の取消を検討してください。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#            remarks += '\nCommonly granted EXECUTE ' + \
#                       'privilege on these packages cannot be revoked in a PDB.\n'
            remarks += '\n一般的にこれらのパッケージに対して付与されたEXECUTE権限は、PDBで取り消すことはできません。\n'

        refs = {'CIS': 
            'Recommendation 4.1.19, 4.1.20, 4.2.2'}
#        sat.finding('Data Exfiltration', 'PRIV.EXFIL',
#            summary, severity, details, remarks, refs)
        sat.finding('データの持ち出し'.decode('utf-8'), 'PRIV.EXFIL',
            summary, severity, details, remarks.decode('utf-8'), refs)

    priv_grants = [[x[p_grantee], x[p_priv], x[p_admin], 
        'NO' if p_common == None else x[p_common]] for
        x in system_privs]
    heading = 'Grants of system privileges to PUBLIC'
    desc = 'system privileges to PUBLIC'
    severity, summary, details = \
        priv_grant_details(priv_grants, role_dict, 'admin',
            heading, desc, public_only=True)
#    remarks = 'Privileges granted to PUBLIC are available to all ' + \
#        'users. This generally should include few, if any, ' + \
#        'system privileges since these will not be needed by ordinary ' + \
#        'users who are not administrators.'
    remarks = 'PUBLICに与えられるシステム権限はすべてのユーザが利用可能です。これが一般的に必要' + \
        'なケースはほとんどありません。もしあるとしても、PUBLICからのシステム権限が、管理' + \
        '者でもない一般ユーザによって必要とされることはないでしょう。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted ' + \
#                    'privileges to PUBLIC cannot be revoked in a PDB.\n'
         remarks += '\n一般的にPUBLICに付与された権限は、PDBで取り消すことはできません。\n'
    refs = {'STIG': 'Rule SV-75925r1' }
#    sat.finding('System Privileges Granted to PUBLIC', 'PRIV.SYSPUB', summary,
#        severity, details, remarks, refs)
    sat.finding('PUBLICに付与されたシステム権限'.decode('utf-8'), 'PRIV.SYSPUB', summary,
        severity, details, remarks.decode('utf-8'), refs)

    heading = 'Grants of roles to PUBLIC'
    desc = 'roles to PUBLIC'
    severity, summary, details = \
        role_grant_details(role_dict, None, heading, desc, public_only=True)
    if summary == NO_USER_GRANTED + desc:
       summary = 'PUBLIC has not been granted any role.'
#    remarks = 'Roles granted to PUBLIC are available to all users. ' + \
#              'Most roles contain privileges that are not appropriate ' + \
#              'for all users. Use Privilege Analysis to identify if these ' + \
#              'privileges were used. If not, work with Oracle support ' + \
#              'and/or application provider to revoke them if possible.'
    remarks = 'PUBLICに与えられるROLEはすべてのユーザが利用可能です。多くのロールは、すべてのユ' + \
        'ーザに適切ではない権限を含んでいます。' + \
		'Privilege Analysisを使用して、これらの権限が使用されるかを識別します。' + \
		'使用されない場合、可能であれば、Oracleサポートおよび/またはアプリケーション・プロバイダ' + \
		'に連絡して、該当権限を取り消します。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted roles' + \
#                    'to PUBLIC cannot be revoked in a PDB.\n'
         remarks += '\n一般にPUBLICに付与されたロールは、PDBで取り消すことはできません。\n'

    refs = {'STIG': 'Rule SV-75933r1' }
#    sat.finding('Roles Granted to PUBLIC', 'PRIV.ROLEPUB', summary,
#        severity, details, remarks, refs)
    sat.finding('PUBLICに付与されたロール'.decode('utf-8'), 'PRIV.ROLEPUB', summary,
        severity, details, remarks.decode('utf-8'), refs)

    if column_privs is None:
        sat.diag('Skipped Column Privilege checks')
    else:
        priv_grants = [[x[c_grantee],
             x[c_priv]+' on '+x[c_owner]+'.'+x[c_table]+'('+x[c_column]+')',
             x[c_admin], 'NO' if c_common == None else x[c_common]] for x in column_privs]
        heading = 'Grants of column privileges to PUBLIC'
        desc = 'column privileges to PUBLIC'
        severity, summary, details = \
            priv_grant_details(priv_grants, role_dict, 'grant',
                heading, desc, public_only=True)
#        remarks = 'Privileges granted to PUBLIC are available to all ' + \
#            'users. This should include column privileges only for ' + \
#            'data that is intended to be accessible to everyone.'
        remarks = 'PUBLICに与えられる権限はすべてのユーザが利用可能です。これは誰でもアクセスできる' + \
            'データのみだけにカラム権限を含めるべきです。'
        if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted privileges on columns to ' + \
#                    'PUBLIC cannot be revoked in a PDB.\n'
         remarks += '\n一般にPUBLICに付与されたカラム権限は、PDBで取り消すことはできません。\n'

     
#        sat.finding('Column Privileges Granted to PUBLIC', 'PRIV.COLPUB',
#            summary, severity, details, remarks)
        sat.finding('PUBLICに付与されたカラム権限'.decode('utf-8'), 'PRIV.COLPUB',
            summary, severity, details, remarks.decode('utf-8'))
     
    user_password_file()

    heading = 'Grants of DBA role'
    desc = 'highly sensitive DBA role'
    severity, summary, details = \
        role_grant_details(role_dict, ('DBA',), heading, desc)
#    remarks = 'The DBA is a powerful role and can be used to bypass ' + \
#        'many security controls. It should be granted to ' + \
#        'a small number of trusted administrators.\n' + \
#        'As a best practice, it is recommended to create custom DBA-like ' + \
#        'roles with minimum set of privileges that users require to execute '+ \
#        'their tasks (least privilege principle) and do not grant the DBA ' + \
#        'role. Privilege Analysis can assist in the task of identifying ' + \
#        'used/unused privileges and roles.\nHaving different roles with ' + \
#        'minimum required privileges ' + \
#        'based on types of operations DBAs execute also helps to achieve ' + \
#        'Separation of Duties.\nFurthermore, ' + \
#        'each trusted user should have an individual account for ' + \
#        'accountability reasons. ' + \
#        'It is recommended to audit users with the DBA roles to detect ' + \
#        'any unauthorized activity. ' + \
#        'Avoid granting the DBA or custom DBA-like powerful roles WITH ADMIN '+\
#        'option unless absolutely necessary.\nPlease note that Oracle may ' + \
#        'add or remove roles and privileges from the DBA role.'
    remarks = 'DBAロールは非常に強力で多くのセキュリティコントロールをバイパスすることができます。信用' + \
        'できる少数の管理者に対して付与するべきです。\n' + \
		'ベストプラクティスとして、ユーザーが自分のタスクを実行するために必要な最小限の権限セット（最小権限の原則）' + \
		'を持つDBAのようなカスタムロールを作成し、DBAロールを付与しないことを推奨します。' + \
		'Privilege Analysis機能は、使用済/未使用の権限およびロールを識別するタスクを支援します。\n' + \
		'DBAが実行する操作の種類に基づいて必要最小限の権限でさまざまなロールを持つことも、' + \
		'職務分離を実現するのに役立ちます。\n' + \
		'その上にそれぞれの信頼できるユーザには、' + \
        '説明責任を持たせるために個々のアカウントを持つようにする必要があります。' + \
        'DBAロールを持つユーザーを監査して、不正なアクティビティを検出することをお勧めします。' + \
        '本当に必要がない限りは、DBAロールまたは、DBAのような強力なカスタムロールをWITH ADMINオプションで' + \
        '付与することを避けます。\n' + \
		'Oracleは、DBAロールにロールおよび権限を追加または削除することがありますのでご了承ください。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted DBA role ' + \
#                    'cannot be revoked in a PDB.\n'
         remarks += '\n一般に付与されたDBAロールは、PDBで取り消すことはできません。\n'
    refs = {'CIS': 'Recommendation 4.4.4'}
#    sat.finding('Users with DBA Role', 'PRIV.DBA', summary,
#        severity, details, remarks, refs)
    sat.finding('DBAロールを持つユーザー'.decode('utf-8'), 'PRIV.DBA', summary,
        severity, details, remarks.decode('utf-8'), refs)

    role_list = ('AQ_ADMINISTRATOR_ROLE', 'EM_EXPRESS_ALL', 'EXP_FULL_DATABASE',
        'IMP_FULL_DATABASE', 'SELECT_CATALOG_ROLE', 'EXECUTE_CATALOG_ROLE',
        'DELETE_CATALOG_ROLE', 'OEM_MONITOR', 'DBA')
    heading = 'Grants of %s roles' % join_list(role_list)
    desc = 'powerful roles'
    severity, summary, details = \
        role_grant_details(role_dict, role_list, heading, desc)
#    remarks = 'DBA and other similarly powerful roles ' + \
#        '(' + join_list(role_list) + ') ' + \
#        'contain powerful privileges that can be used to bypass security ' + \
#        'protections. They should be granted only to a small ' + \
#        'number of trusted administrators. It is recommended to audit users '+ \
#        'with these roles to detect any unauthorized activity. ' + \
#        'Use Privilege Analysis to identify if these privileges were used. ' + \
#        'If not, consider revoking.'
    remarks = 'DBAおよび他の同様に強力なロール (AQ_ADMINISTRATOR_ROLE, EM_EXPRESS_ALL, EXP_FULL_DATABASE, ' + \
        'IMP_FULL_DATABASE, SELECT_CATALOG_ROLE, DELETE_CATALOG_ROLE, OEM_MONITOR, DBA)は、セキュリティ保護をバイパス' + \
        'することができる権限を含んでいます。それらは、信用できる少数の管理者に対してのみ付与するべきです。' + \
		'これらのロールを持つユーザーを監査して、許可されていない活動を検出することをお勧めします。' + \
		'Privilege Analysisを使用して、これらの権限が使用されるかを識別します。' + \
		'使用されない場合、これらの権限の取消を検討してください。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted above powerful roles ' + \
#                    'cannot be revoked in a PDB.\n'
         remarks += '\n一般に付与された上記の強力なロールは、PDBで取り消すことはできません。\n'
    refs = {'CIS': 'Recommendation 4.4.1, 4.4.2, 4.4.3', 
            'STIG': 'Rule SV-75927r3'}
#    sat.finding('Users with Powerful Roles', 'PRIV.BIGROLES', summary,
#        severity, details, remarks, refs)
    sat.finding('強力な権限を持つユーザー'.decode('utf-8'), 'PRIV.BIGROLES', summary,
        severity, details, remarks.decode('utf-8'), refs)

def java_permission():
    data = sat.get_data('java_permission', 1)
    if data is None:
        sat.diag('Skipped Java Permissions')
        return

    grantee = sat.get_index('java_permission', 'grantee')
    kind = sat.get_index('java_permission', 'kind')
    t_name = sat.get_index('java_permission', 'type_name')
    t_schema = sat.get_index('java_permission', 'type_schema')
    name = sat.get_index('java_permission', 'name')
    action = sat.get_index('java_permission', 'action')

    details = ''
    g_user = None
    num_grantees = 0
    if con_type == 'PDB':
       users_to_report = all_local_users + all_roles + ['PUBLIC']
    else:
       users_to_report = all_users + all_roles + ['PUBLIC']

    for x in data:
        if x[grantee] not in users_to_report:
            continue

        if g_user is None:
            details += 'Grantee: ' + x[grantee] + '\n'
            num_grantees += 1
        elif g_user != x[grantee]:
            details += '\nGrantee: ' + x[grantee] + '\n'
            num_grantees += 1

        details += x[kind] + ', '
        details += 'Name: ' + x[name] + ', '
        details += 'Type Schema: ' + x[t_schema] + ', '
        details += 'Type Name: ' + x[t_name]
        if len(x[action]) > 0:
            details += ', Action: ' + x[action]
        details += '\n'
        g_user = x[grantee]

    if num_grantees > 0:
        summary = 'Found ' + sing_plural(num_grantees, 'user or role',
                                                       'users or roles') + \
                  ' with Java permission.'
    else:
        summary = 'No users or roles granted Java permission found.'

    if len(data) > 0:
        severity = sat.SEV_UNKNOWN
    else:
        severity = sat.SEV_OK

#    remarks = 'Java permission grants control the ability of database ' + \
#        'users to execute Java classes within the database server. ' + \
#        'A database user executing Java code must have both Java security ' + \
#        'permissions and database privileges to access resources within ' + \
#        'the database. These resources include database ' + \
#        'resources, such as tables and PL/SQL packages, operating system ' + \
#        'resources, such as files and sockets, Oracle JVM classes, and ' + \
#        'user-loaded classes. Make sure that these permissions are ' + \
#        'limited to the minimum required by each user. ' + \
#        'Use Privilege Analysis to identify if these privileges were used. ' + \
#        'If not, consider revoking.'
    remarks = 'Javaパーミッションはデータベースユーザがデータベース内でJavaクラスを実行する権限' + \
        'を付与します。データベースユーザが実行するJavaコードは、Javaのセキュリティパーミッ' + \
        'ションとデータベースのアクセス権限の両方を持たなければなりません。これらのリソー' + \
        'スはデータベースのリソースに含まれており、例えば、PL/SQLパッケージやOSシステム、' + \
        'ファイルやソケット、Oracle JVMクラスなどです。これらのパーミッションがそれぞれの' + \
        'ユーザで最小限に制限されているか確認が必要です。' + \
		'Privilege Analysisを使用して、これらの権限が使用されるかを識別します。' + \
		'使用されない場合、これらの権限の取消を検討してください。'
    if severity != sat.SEV_OK and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted Java permissions ' + \
#                    'cannot be revoked in a PDB.\n'
         remarks += '\n一般に付与されたJavaパーミッションは、PDBで取り消すことはできません。\n'

#    sat.finding('Java Permissions', 'PRIV.JAVA', summary,
#        severity, details, remarks)
    sat.finding('Javaパーミッション'.decode('utf-8'), 'PRIV.JAVA', summary,
        severity, details, remarks.decode('utf-8'))

def user_password_file():
    data = sat.get_data('user_password_file', 1)
    if data is None:
        sat.diag('Skipped Administrative Privileges')
        return

    name = sat.get_index('user_password_file', 'username')
    sysdba = sat.get_index('user_password_file', 'sysdba')
    sysoper = sat.get_index('user_password_file', 'sysoper')
    sysbackup = sat.get_index('user_password_file', 'sysbackup')
    sysdg = sat.get_index('user_password_file', 'sysdg')
    syskm = sat.get_index('user_password_file', 'syskm')
    common = sat.get_index('user_password_file', 'common')

    sysdba_user_list = []
    sysoper_user_list = []
    sysbackup_user_list = []
    sysdg_user_list = []
    syskm_user_list = []
    found_common = False
    if sysdba is not None and common is not None:
        if con_type == 'PDB':
            sysdba_user_list = [x[name] for x in data if x[sysdba] and not x[common]]
        else:
            sysdba_user_list = [x[name] for x in data if x[sysdba]]
            found_common = True if len(sysdba_user_list) > 0 else False
    if sysoper is not None:
        if con_type == 'PDB' and common is not None:
            sysoper_user_list = [x[name] for x in data if x[sysoper] and not x[common]]
        else:
            sysoper_user_list = [x[name] for x in data if x[sysoper]]
            found_common = True if len(sysoper_user_list) > 0 else False
    if sysbackup is not None:
        if con_type == 'PDB' and common is not None:
            sysbackup_user_list = [x[name] for x in data if x[sysbackup] and not x[common]]
        else:
            sysbackup_user_list = [x[name] for x in data if x[sysbackup]]
            found_common = True if len(sysbackup_user_list) > 0 else False
    if sysdg is not None:
        if con_type == 'PDB' and common is not None:
            sysdg_user_list = [x[name] for x in data if x[sysdg] and not x[common]]
        else:
            sysdg_user_list = [x[name] for x in data if x[sysdg]]
            found_common = True if len(sysdg_user_list) > 0 else False
    if syskm is not None:
        if con_type == 'PDB' and common is not None:
            syskm_user_list = [x[name] for x in data if x[syskm] and not x[common]]
        else:
            syskm_user_list = [x[name] for x in data if x[syskm]]
            found_common = True if len(syskm_user_list) > 0 else False
             

    all_grantees = sysdba_user_list + sysoper_user_list + \
       sysbackup_user_list + sysdg_user_list + syskm_user_list
    all_grantees = set(all_grantees)
    ungranted_privs = 0;

    if sysdba is not None and len(sysdba_user_list) == 0:
        ungranted_privs += 1
    if sysoper is not None and len(sysoper_user_list) == 0:
        ungranted_privs += 1
    if sysbackup is not None and len(sysbackup_user_list) == 0:
        ungranted_privs += 1
    if sysdg is not None  and len(sysdg_user_list) == 0:
        ungranted_privs += 1
    if syskm is not None and len(syskm_user_list) == 0:
        ungranted_privs += 1

    if ungranted_privs > 0:
        severity = sat.SEV_LOW
    else:
        severity = sat.SEV_UNKNOWN

    if len(all_grantees) > 0:
        summary = 'Found ' + sing_plural(len(all_grantees), 'user', 'users') + \
                  ' granted administrative SYS* privileges. '
    else:
        summary = 'No user has been granted administrative SYS* privileges. '
    if ungranted_privs > 0:
       if len(all_grantees) > 0:
         summary += 'Found ' + sing_plural(ungranted_privs, 
                            ' administrative SYS* privilege',
                            ' administrative SYS* privileges') + \
                   ' not granted to any user.'
    else:
        summary += 'Each SYS* administrative privilege is granted to one or more users.'

    details = 'SYSDBA    (%d): ' % len(sysdba_user_list) + \
              join_list(sysdba_user_list) + '\n'
    details += 'SYSOPER   (%d): ' % len(sysoper_user_list) + \
              join_list(sysoper_user_list) +  '\n'
    if sysbackup:
        details += 'SYSBACKUP (%d): ' % len(sysbackup_user_list) + \
                   join_list(sysbackup_user_list) + '\n'
    if sysdg:
        details += 'SYSDG     (%d): ' % len(sysdg_user_list) + \
                   join_list(sysdg_user_list) + '\n'
    if syskm:
        details += 'SYSKM     (%d): ' % len(syskm_user_list) + \
                   join_list(syskm_user_list) + '\n'

#    remarks = 'Administrative SYS* privileges allow a user to perform ' + \
#        'maintenance operations, including some that may occur ' + \
#        'while the database is not open. The SYSDBA privilege ' + \
#        'allows the user to run as SYS and perform virtually all ' + \
#        'privileged operations. Starting with Oracle Database ' + \
#        '12.1, less powerful administrative privileges were ' + \
#        'introduced to allow users to perform specific  ' + \
#        'administrative tasks with less than full SYSDBA ' + \
#        'privileges. To achieve the benefit of this separation ' + \
#        'of duty, each of these administrative privileges should ' + \
#        'be granted to at least one named user account.'
    remarks = '管理者SYS*権限は、データベースがオープンされていない時に発生するかもしれないものも含' + \
        'めて、ユーザがメンテナンス操作を実行することを可能にします。SYSDBA権限はSYSとし' + \
        'ての操作することを許可し、実質的にすべての操作が可能となります。Oracle Database ' + \
        '12.1以降では、特定の管理者タスクをSYSDBAより小さい権限で実施できるように、小さな' + \
        '管理者権限での操作が紹介されています。権限分掌を実現させるために、これらの管理者' + \
        '権限は少なくともひとつの名前付きユーザアカウントに付与されるべきです。'
    if found_common == True and con_type == 'PDB_COMPREHENSIVE':
#         remarks += '\nCommonly granted Administrative SYS* ' + \
#                    'privileges cannot be revoked in a PDB.\n'
         remarks += '\n一般に付与された管理者SYS*権限は、PDBで取り消すことはできません。\n'
    refs = {'STIG': 'Rule SV-76081r3'}
#    sat.finding('Users with Administrative SYS* Privileges', 'PRIV.ADMIN',
#        summary, severity, details, remarks, refs)
    sat.finding('管理者SYS*権限を持つユーザ'.decode('utf-8'), 'PRIV.ADMIN',
        summary, severity, details, remarks.decode('utf-8'), refs)

def priv_grant_recur(grantee, prefix, priv_grants, role_grants, check_local_grant = True):
    grantee_is_user = False
    if prefix == '':
        prefix = grantee
        grantee_is_user = True
    else:
        prefix = prefix + ' <- ' + grantee
    directs = priv_grants.get(grantee, [])
    if con_type == 'PDB' and check_local_grant:
      list1 = [x[0]+'(*)' for x in directs if x[1] and x[2] == 'NO']
      list2 = [x[0] for x in directs if not x[1] and x[2] == 'NO']
    else:
      list1 = [x[0]+'(*)' for x in directs if x[1]]
      list2 = [x[0] for x in directs if not x[1]]
    num_admin = len(list1)
    num_total = num_admin + len(list2)
    if num_total == 0:
        details = ''
    else:
        details = '%s: %s\n' % (prefix, join_list(sorted(list1 + list2)))
    if grantee_is_user and con_type == 'PDB':
      roles_granted = [x[0] for x in role_grants.get(grantee, []) if x[2] == 'NO'] 
    else:
      roles_granted = [x[0] for x in role_grants.get(grantee, [])]
    roleset = set(roles_granted)
    for role in sorted(roles_granted):
        (role_total, role_admin, role_details, role_roleset) = \
            priv_grant_recur(role, prefix, priv_grants, role_grants, False)
        num_total += role_total
        num_admin += role_admin
        details += role_details
        roleset |= role_roleset

    return (num_total, num_admin, details, roleset)

def priv_grant_details(priv_grants, role_grants, admin_name,
                         heading, desc, public_only=False):
    num_total = 0
    num_admin = 0
    details = ''
    pub_summary = ''
    pub_severity = sat.SEV_OK
    num_users_roles = 0
    num_admin_grant = 0
    priv_dict = {}
    for x in priv_grants:
        priv_dict[x[0]] = priv_dict.get(x[0], []) + [[x[1], x[2], x[3]]]
    num_total, num_admin, pub_details, roleset = \
        priv_grant_recur('PUBLIC', '', priv_dict, role_grants)
    if num_total > 0:
        details = pub_details + '\n'
        pub_summary = sing_plural(num_total, 'grant', 'grants') + ' to PUBLIC.'
        pub_severity = sat.SEV_HIGH
        num_users_roles += 1
    else:
        pub_summary = 'No grants to PUBLIC.'
    if num_admin > 0:
        num_admin_grant += 1

    if not public_only:
        for name in all_users:
            (name_total, name_admin, name_details, name_roleset) = \
                priv_grant_recur(name, '', priv_dict, role_grants)
            num_total += name_total
            num_admin += name_admin
            if name_details != '':
                details += name_details + '\n'
                num_users_roles += 1
            if name_admin > 0:
                num_admin_grant += 1

            roleset |= name_roleset

        if show_unassigned_roles_privs:
          roles = set(all_roles)
          roles -= roleset
          for name in sorted(list(roles)):
              (name_total, name_admin, name_details, name_roleset) = \
                  priv_grant_recur(name, '(no users)', priv_dict, role_grants)
              num_total += name_total
              num_admin += name_admin
              if name_details != '':
                  details += name_details + '\n'
                  num_users_roles += 1
              if name_admin > 0:
                  num_admin_grant += 1


    if num_admin > 0:
        details += '(*)  = granted with %s option' % admin_name
        details += '\n(<-) = granted via'
    if details:
        details = heading + ':\n\n' + details
    severity, summary = grant_summary(desc, admin_name, num_total, num_admin, len(all_users), num_users_roles,num_admin_grant,0)
    if pub_summary:
        severity = max(severity, pub_severity)
        if not public_only:
            summary += ' ' + pub_summary
        else:
            summary = pub_summary 

    return (severity, summary, details)

def role_grant_recur(grantee, prefix, role_grants, role_list):
    grantee_is_prefix = False
    if prefix == '':
        prefix = grantee
        grantee_is_prefix = True
    else:
        prefix = prefix + ' <- ' + grantee

    if grantee_is_prefix and con_type == 'PDB':
       direct_roles = [x for x in role_grants.get(grantee, []) if x[2] == 'NO'] 
    else:
      direct_roles = [x for x in role_grants.get(grantee, [])]
    if role_list == None:
        directs = direct_roles
    else:
        directs = [x for x in direct_roles if x[0] in role_list]
    list1 = [x[0]+'(*)' for x in directs if x[1]]
    list2 = [x[0] for x in directs if not x[1]]
    num_admin = len(list1)
    num_total = num_admin + len(list2)
    if num_total == 0:
        details = ''
    else:
        details = '%s: %s\n' % (prefix, join_list(list1 + list2))

    roles_granted = [x[0] for x in direct_roles]
    roleset = set(roles_granted)
    for role in sorted(roles_granted):
        (role_total, role_admin, role_details, role_roleset) = \
            role_grant_recur(role, prefix, role_grants, role_list)
        num_total += role_total
        num_admin += role_admin
        details += role_details
        roleset |= role_roleset

    return (num_total, num_admin, details, roleset)

def role_grant_details(role_grants, role_list, heading, desc, public_only=False):
    num_total = 0
    num_admin = 0
    details = ''
    pub_summary = ''
    num_total_unique = 0  # Total number of users granted via single or multiple routes.
    unique_grantee = []   # List of unique grantees.
    num_admin_grant = 0

    num_total, num_admin, pub_details, roleset = \
        role_grant_recur('PUBLIC', '', role_grants, role_list)
    if num_total > 0:
        details = pub_details + '\n'
        pub_summary = sing_plural(num_total, 'grant', 'grants') + ' to PUBLIC.'

    if not public_only:
        for name in all_users:
            (name_total, name_admin, name_details, name_roleset) = \
                role_grant_recur(name, '', role_grants, role_list)
            num_total += name_total # More than one grant route can exist for a user.
            num_admin += name_admin # A user can be granted with admin option via more than one route.
            if name_total > 0:
                if name not in unique_grantee:
                   unique_grantee.append(name)
            if name_details != '':
                details += name_details + '\n'
            roleset |= name_roleset
            if name_admin > 0:
                  num_admin_grant += 1
        num_total_unique = len(unique_grantee)

        if show_unassigned_roles_privs:
          roles = set(all_roles)
          roles -= roleset
          for name in sorted(list(roles)):
              (name_total, name_admin, name_details, name_roleset) = \
                  role_grant_recur(name, '(no users)', role_grants, role_list)
              num_total += name_total
              num_admin += name_admin
              if name_details != '':
                  details += name_details + '\n'
              if name_admin > 0:
                  num_admin_grant += 1

    if num_admin > 0:
        details += '(*) = granted with admin option'
    if details:
        details = heading + ':\n\n' + details
    severity, summary = grant_summary(desc, 'admin', num_total, num_admin, len(all_users), num_total_unique, num_admin_grant, 0)
    if pub_summary:
        severity = sat.SEV_HIGH
        if not public_only:
            summary += ' ' + pub_summary 

    return (severity, summary, details)

NO_USER_GRANTED = 'No users granted '
def grant_summary(desc, admin_name, num_total, num_admin, num_all = 0, num_total_unique = 0, num_admin_unique = 0, num_direct_unique = 0):
    if num_total == 0:
        msg = NO_USER_GRANTED + desc
        severity = sat.SEV_OK
    else:
        severity = sat.SEV_UNKNOWN
        if num_total == 1:
            msg = '%d out of %d users have been directly or indirectly granted %s via %d grant.\n' % (num_total_unique, num_all, desc, num_total)
        else:
            msg = '%d out of %d users have been directly or indirectly granted %s via %d grants.\n' % (num_total_unique, num_all, desc, num_total)
    if num_admin > 0:
        if num_admin_unique == 1:
            msg += ' 1 user is granted %s with %s option via %s.\n' % (desc, admin_name, sing_plural(num_admin, 'grant', 'grants'))
        else:
            msg += ' %d users are granted %s with %s option via %s.\n' % (num_admin_unique, desc, admin_name, sing_plural(num_admin, 'grant', 'grants'))
    return severity, msg

def filter_system_privs(syspriv_grants, priv_list):
    if priv_list:
        priv_grants = [x for x in syspriv_grants if x[1] in priv_list]
        heading = 'Grants of ' + join_list(priv_list)
    else:
        priv_grants = syspriv_grants
        heading = 'Grants of system privileges'
    return priv_grants, heading

def get_role_grantees(role, role_grants, r_grantee, r_role):
    users = []

    for rg in role_grants:
        if rg[r_role] == role:
            grantee = rg[r_grantee]
            if grantee in all_roles:
                users += get_role_grantees(grantee, 
                             role_grants, r_grantee, r_role)
            elif grantee in acct_profiles:
                users.append(grantee)

    return sorted(list(set(users)))

def get_local_role_grantees(role, role_grants, r_grantee, r_role, r_common):
    users = []

    for rg in role_grants:
        if rg[r_role] == role:
           if rg[r_common] == 'NO':
             grantee = rg[r_grantee]
             if grantee in all_roles:
                 users += get_local_role_grantees(grantee,
                              role_grants, r_grantee, r_role, r_common)
             elif grantee in acct_profiles:
                 users.append(grantee)

    return sorted(list(set(users)))


def get_sys_priv_grantees(priv, chk_direct = False):
    system_privs = sat.get_data('system_privs', 0)
    role_grants = sat.get_data('role_grants', 0)
    if system_privs is None or role_grants is None or all_roles is None:
        sat.diag('Skipped Get System Privilege Grantees')
        return None
    s_grantee = sat.get_index('system_privs', 'grantee')
    s_priv = sat.get_index('system_privs', 'privilege')
    s_admin = sat.get_index('system_privs', 'is_admin')
    s_common = sat.get_index('system_privs', 'common')
    r_grantee = sat.get_index('role_grants', 'grantee')
    r_role = sat.get_index('role_grants', 'granted_role')
    r_common = sat.get_index('role_grants', 'common')

    has_admin = {}
    has_direct = {}
    has_common = {}
    num_direct = 0
    num_all = 0            
    num_unique_grantees = 0 
    unique_grantees = []
    unique_admin_grantees = []  
    unique_direct_grantees = [] 
                                
    for x in system_privs:
        if x[s_priv] == priv:
            grantee = x[s_grantee]
            admin = x[s_admin]
            if grantee in all_roles:
                if con_type == 'PDB':
                   for u in get_local_role_grantees(grantee, role_grants, 
                   r_grantee, r_role, r_common):
                       has_admin[u] = has_admin.get(u, False) | admin
                       has_direct[u] = has_direct.get(u,False) | False 
                       if u not in unique_grantees:
                          unique_grantees.append(u)
                       if has_admin[u] and u not in unique_admin_grantees:
                          unique_admin_grantees.append(u)
                else:
                   for u in get_role_grantees(grantee, role_grants,
                   r_grantee, r_role):
                       has_admin[u] = has_admin.get(u, False) | admin
                       has_direct[u] = has_direct.get(u,False) | False
                       if con_type == 'PDB_COMPREHENSIVE':
                          if u in get_local_role_grantees(grantee, role_grants,
                                                  r_grantee, r_role, r_common):
                             has_common[u] = False
                          else:
                             has_common[u] = True
                       if u not in unique_grantees:
                          unique_grantees.append(u)
                       if has_admin[u] and u not in unique_admin_grantees:
                          unique_admin_grantees.append(u)
            elif grantee in acct_profiles: 
                if con_type == 'PDB':  
                   if x[s_common] == 'NO':
                      has_admin[grantee] = has_admin.get(grantee, False) | admin
                      has_direct[grantee] = has_direct.get(grantee, True) | True
                      if grantee not in unique_grantees:
                         unique_grantees.append(grantee)
                      if has_admin[grantee] and \
                         grantee not in unique_admin_grantees:
                            unique_admin_grantees.append(grantee)
                      if has_direct[grantee] and \
                         grantee not in unique_direct_grantees:
                            unique_direct_grantees.append(grantee)

                else:
                   has_admin[grantee] = has_admin.get(grantee, False) | admin
                   has_direct[grantee] = has_direct.get(grantee,True) | True
                   if con_type == 'PDB_COMPREHENSIVE' and x[s_common] == 'YES':
                      has_common[grantee] = True
                   else:
                      has_common[grantee] = False
                   if grantee not in unique_grantees:
                      unique_grantees.append(grantee)
                   if has_admin[grantee] and grantee not in unique_admin_grantees:
                      unique_admin_grantees.append(grantee)
                   if has_direct[grantee] and grantee not in unique_direct_grantees:
                      unique_direct_grantees.append(grantee)

    users = []
    num_admin = 0
    for u in sorted(has_admin.keys()):
        if has_admin[u]:
            if has_direct[u] and chk_direct:
               if con_type == 'PDB_COMPREHENSIVE' and has_common[u] == True:
                  users.append(u + '(D)' + '(*)' + '(C)')
               else:
                  users.append(u + '(D)' + '(*)')
               num_direct += 1
            else:
               users.append(u + '(*)')
            num_admin += 1
        else:
            if has_direct[u] and chk_direct:
               if con_type == 'PDB_COMPREHENSIVE' and has_common[u] == True:
                  users.append(u + '(D)' + '(C)')
               else:
                  users.append(u + '(D)')
               num_direct += 1
            else:
               users.append(u)
    if chk_direct:
       return users, unique_grantees, num_admin, unique_admin_grantees, num_direct, unique_direct_grantees
    else:
       return users, unique_grantees, num_admin

def get_execute_grantees(package):
    exec_data = sat.get_data('execute_privs', 2)
    role_grants = sat.get_data('role_grants', 0)

    if exec_data is None or role_grants is None:
        return None

    p_grantee = sat.get_index('execute_privs', 'grantee')
    p_priv = sat.get_index('execute_privs', 'privilege')
    p_name = sat.get_index('execute_privs', 'package')
    p_common = sat.get_index('execute_privs', 'common')
    r_grantee = sat.get_index('role_grants', 'grantee')
    r_role = sat.get_index('role_grants', 'granted_role')
    r_common = sat.get_index('role_grants', 'common')

    users = set()
    for x in exec_data:
        if x[p_name] == package and x[p_priv] == 'EXECUTE':
            grantee = x[p_grantee]
            if grantee in all_roles:
                if con_type == 'PDB':
                   for u in get_local_role_grantees(grantee, role_grants, 
                   r_grantee, r_role, r_common):
                       users = users.union(set([u]))
                else:
                   for u in get_role_grantees(grantee, role_grants,
                   r_grantee, r_role):
                       users = users.union(set([u]))
            elif grantee in acct_profiles: 
                if con_type == 'PDB':
                   if  x[p_common] == 'NO':# if PDB use local grants
                       users = users.union(set([grantee]))
                else:
                   users = users.union(set([grantee]))

    return sorted(list(users))


def database_vault():
    dv_option = db_options_dict.get('Oracle Database Vault', False)
    severity = sat.SEV_UNKNOWN
    summary = ''
    details = ''

    if not dv_option:
        severity = sat.SEV_ENHANCEMENT
        summary = 'Database Vault is not enabled.'
        details = None
    else:
        dv_rlm_data = sat.get_data('dv_realm', 1)
        dv_cmd_rule_data = sat.get_data('dv_command_rule', 1)
        dv_rlm_obj_data = sat.get_data('dv_realm_object', 1)
        dv_status = sat.get_data('dv_status', 1)

        if dv_rlm_data is None and dv_cmd_rule_data is None and \
           dv_rlm_obj_data is None:
            sat.diag('Skipped Database Vault Checks')
            return
        else:
            rlm_name = sat.get_index('dv_realm', 'name')
            rlm_enabled = sat.get_index('dv_realm', 'enabled')
            default_realm = sat.get_index('dv_realm', 'oracle_supplied')

            name = sat.get_index('dv_realm_object', 'realm_name')
            owner = sat.get_index('dv_realm_object', 'owner')
            obj_name = sat.get_index('dv_realm_object', 'object_name')
            obj_type = sat.get_index('dv_realm_object', 'object_type')

            cmd_rule_enabled = sat.get_index('dv_command_rule', 'enabled')
            cmd_name = sat.get_index('dv_command_rule', 'command')
            obj_owner= sat.get_index('dv_command_rule', 'object_owner')
            obj_name = sat.get_index('dv_command_rule', 'object_name')
            clause = sat.get_index('dv_command_rule', 'clause_name')
            parameter_name = sat.get_index('dv_command_rule', 'parameter_name')
            event_name = sat.get_index('dv_command_rule', 'event_name')
            component_name = sat.get_index('dv_command_rule', 'component_name')
            action_name = sat.get_index('dv_command_rule', 'action_name')
            def_cmd_rule = sat.get_index('dv_command_rule', 'oracle_supplied')

            cmd_rules = []
            for x in dv_cmd_rule_data:
                cmd = x[cmd_name]
                if clause is not None and x[clause] != '%':
                    cmd += ' ' + x[clause]
                if parameter_name is not None and x[parameter_name] != '%': 
                    cmd += ' ' + x[parameter_name]
                if event_name is not None and x[event_name] != '%':
                    cmd += ' ' + x[event_name]
                if component_name is not None and x[component_name] != '%':
                    cmd += ' ' + x[component_name]
                if action_name is not None and x[action_name] != '%':
                    cmd += ' ' + x[action_name]
                if x[obj_owner] == '%':
                    object_owner = '<Any Schema>'
                else:
                    object_owner = x[obj_owner]
                if x[obj_name] == '%':
                    object_name = '<Any Object>'
                else:
                    object_name = x[obj_name]

                if x[obj_owner] != '%' or x[obj_name] != '%':
                    cmd += ' on ' + object_owner + '.' + object_name
               
                if x[cmd_rule_enabled]: 
                    cmd += ' (Enabled)'
                else:
                    cmd += ' (Disabled)'

                if def_cmd_rule and x[def_cmd_rule]:
                    cmd += ' (Default)'
                cmd_rules.append(cmd)

            rlms = []
            for x in dv_rlm_data:
                rlm = x[rlm_name]
                if x[rlm_enabled]:
                    rlm += ' (Enabled)'
                else:
                    rlm += ' (Disabled)' 
                if default_realm and x[default_realm]:
                    rlm += ' (Default)'

                rlm += '\n'
                role_list = [y[obj_name] for y in dv_rlm_obj_data \
                             if y[name] == x[rlm_name] and \
                                y[obj_type] == 'ROLE']
                rlm += 'Protects roles: %s\n' % join_list(role_list)

                obj_list = []
                for y in dv_rlm_obj_data:
                    if y[name] == x[rlm_name] and y[obj_type] != 'ROLE':
                        if y[obj_name] == '%':
                            obj = y[owner] + '.<Any Object>'
                        else:
                            obj = y[owner] + '.' + y[obj_name]
                        if y[obj_type] == '%':
                            obj += ' (Any Type)'
                        else:
                            obj += ' (' + y[obj_type] + ')'
                        obj_list.append(obj)
                rlm += 'Protects objects: %s\n' % join_list(obj_list) 

                rlms.append(rlm)
            
            if len(dv_rlm_data) == 0 and len(dv_cmd_rule_data) == 0:
                severity = sat.SEV_LOW
                summary = 'No Database Vault realms or command rules found.'
            else:
                severity = sat.SEV_UNKNOWN
                summary = 'Found ' + \
                          sing_plural(len(dv_rlm_data), 'Database Vault realm', 
                                      'Database Vault realms') + \
                          ' and ' + \
                          sing_plural(len(dv_cmd_rule_data), 
                                      'command rule.', 'command rules.')
                details += 'Realms:\n'
                details += join_list(rlms, '\n')
                details += '\n\n'
                details += 'Command rules:\n'
                details += join_list(cmd_rules, '\n')

        role_grants = sat.get_data('role_grants', 0)
        sys_role_grants = sat.get_data('sys_role_grants', 1)
        if role_grants is None or sys_role_grants is None or all_roles is None:
            sat.diag('Skipped Database Vault roles grant info')
        else:
            r_grantee = sat.get_index('role_grants', 'grantee')
            r_role = sat.get_index('role_grants', 'granted_role')
            r_common = sat.get_index('role_grants', 'common')
            s_role = sat.get_index('sys_role_grants', 'granted_role')
            sys_roles = [x[s_role] for x in sys_role_grants]

            details += '\n\n'
            dv_roles = ['DV_OWNER', 'DV_ADMIN', 'DV_PATCH_ADMIN', \
                        'DV_AUDIT_CLEANUP', 'DV_ACCTMGR']
            sys_grantable = ['DV_PATCH_ADMIN', 'DV_ACCTMGR']

            for x in dv_roles:
                if con_type == 'PDB':
                   owners = get_local_role_grantees(x, role_grants, r_grantee, r_role, r_common)
                else:
                   owners = get_role_grantees(x, role_grants, r_grantee, r_role)
                if x in sys_grantable:
                    owners.append('SYS')
                if x == 'DV_OWNER':
                    dv_owners = owners
                elif x == 'DV_PATCH_ADMIN':
                    owners = [u for u in owners if u not in dv_owners]
                details += 'Users with %s role: ' % x
                details += join_list(owners) + '\n'

        if target_db_version >= '19':
           if dv_status is not None:
              dv_status_name = sat.get_index('dv_status','name')
              dv_status_status = sat.get_index('dv_status', 'status')        
              for x in dv_status:
                  if x[dv_status_name] == 'DV_APP_PROTECTION':
                     if x[dv_status_status] != 'ENABLED':
                        details += '\nDatabase Vault operations control is ' +\
                                   'not enabled.\n' 
                     else:
                        details += '\nDatabase Vault operations control is ' +\
                                   'enabled.\n'        

#    remarks = 'Database Vault provides for configurable policies ' + \
#          'to control the actions of database accounts with elevated ' + \
#          'privileges such as those accounts used by administrative users, ' + \
#          'applications and utilities.  Attacks (originating from external ' + \
#          'as well as internal sources) leverage privileged account ' + \
#          'credentials to access sensitive information. Database Vault ' + \
#          'realms prevent unauthorized access to sensitive data objects, '+ \
#          'even by user accounts with system privileges. Database Vault Command rules ' + \
#          'limit the accidental or malicious execution of SQL commands. ' + \
#          'You can use Database Vault to enforce ' + \
#          'separation of duties to prevent a single all powerful user.  ' + \
#          'Also it provides trusted paths to further restrict access to ' + \
#          'sensitive data using system factors such as IP address, ' + \
#          'program name, time of day and user name.\n Database Vault ' + \
#          'operations control can be used to restrict common users from ' + \
#          'accessing pluggable database (PDB) local data in autonomous, ' + \
#          'regular Cloud, or on-premises environments.'
    remarks = 'Database Vaultは、管理ユーザー、アプリケーションおよびユーティリティによって使用されるアカウントなど、' + \
        '高い権限を持つデータベースアカウントの操作を制御する変更可能なポリシーを提供します。' + \
		'(内部からの攻撃だけでなく外部からも)攻撃は、特権アカウントの認証情報を利用して機密情報にアクセスします。' + \
        'Database Vaultレルムは、強力なシステム権限を持つユーザアカウントからであっても、' + \
        '機密情報への権限のないアクセスを防ぎます。Database Vaultコマンド・ルールは、' + \
		'想定外または悪意のあるSQLコマンドの実行を制限します。' + \
		'Database Vaultを使用すると、権限分掌を強制して、単一のなんでもできる強力なユーザーを排除できます。' + \
		'また、IPアドレス、プログラム名、時刻、ユーザー名などのシステム要素を使用して、' + \
		'機密データへのアクセスをさらに制限する信頼できるパスを提供します。\n' + \
		'Database Vaultの操作制御を使用して、一般的なユーザーが自律型環境、通常のクラウド環境' + \
        'またはオンプレミス環境でプラガブル・データベース（PDB）のローカル・データにアクセスすることを制限できます。'

    refs = {'GDPR': 'Article 6, 25, 29, 32, 34, 89; Recital 28, 29, 78, 156', 
            'STIG': 'Rule SV-76065r1'}
#    sat.finding('Database Vault', 'AUTH.DV', summary,
#        severity, details, remarks, refs)
    sat.finding('Database Vault', 'AUTH.DV', summary,
        severity, details, remarks.decode('utf-8'), refs)

def privilege_capture():
    data = sat.get_data('privilege_capture', 1)
    if data is None:
        if target_db_version >= '12.1':
            sat.diag('Skipped Privilege Analysis')
        return

    if len(data) > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Found ' + \
                  sing_plural(len(data), 'Privilege Analysis policy.', 
                                         'Privilege Analysis policies.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No Privilege Analysis policies found.'

    name = sat.get_index('privilege_capture', 'name')
    type = sat.get_index('privilege_capture', 'type')
    enabled = sat.get_index('privilege_capture', 'enabled')
    begin = sat.get_index('privilege_capture', 'last_begin');
    end = sat.get_index('privilege_capture', 'last_end')

    details = ''

    for x in data:
        details += 'Policy ' + x[name] + ' (Type: ' + x[type] + ', '
        if x[enabled]:
            details += 'Currently running)\n'
        elif len(x[begin]) == 0 or len(x[end]) == 0:
            details += 'Never been run)\n'
        else:
            begin_time = format_date(read_date(x[begin]))
            end_time = format_date(read_date(x[end]))
            details += 'Latest run: ' + begin_time + ' - ' + end_time + ')\n'

    exec_users = get_execute_grantees('DBMS_PRIVILEGE_CAPTURE')
    if exec_users is not None:
        details += 'Users who can start the privilege analysis capture process: '
        details += join_list(exec_users)

#    remarks = 'Privilege Analysis records the privileges ' + \
#        'used during a ' + \
#        'real or simulated workload. After collecting data about ' + \
#        'the privileges that are actually used, this information can be ' + \
#        'used to revoke privilege grants that are no longer needed or to ' + \
#        'create roles with only the privileges that are used by the user or role. '+\
#        'This helps in implementing Least Privileged Model and allows to ' + \
#        'minimize risk involved in using unused or lesser used privileges ' + \
#        'granted to a user.'
    remarks = 'Privilege Analysisは、実際のデータベースのワークロード中に使用されたユーザ権限を' + \
        '記録します。この情報はすでに使用されていない権限を明確にし、削除することに使用できます。' + \
		'或いは、ユーザーまたはロールによって使用される権限のみを使用してロールを作成します。' + \
		'これは、最小権限モデルの実装に役立ち、ユーザーに付与された未使用または' + \
		'使用頻度の低い権限の使用に伴うリスクを最小限に抑えることができます。'

#    sat.finding('Privilege Analysis', 'AUTH.PRIV', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('Privilege Analysis', 'AUTH.PRIV', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))


def data_encryption():
    tdata = sat.get_data('encrypted_tablespace', 2)
    enc_ts = []
    summary = ''
    details = ''

    if tdata is None:
        sat.diag('Skipped Encrypted Tablespaces')
    else:
        name = sat.get_index('encrypted_tablespace', 'name')
        algo = sat.get_index('encrypted_tablespace', 'algo')
        unenc_ts = []

        for x in tdata:
            if len(x[algo]) > 0:
                enc_ts.append(x[name] + ' (' + x[algo] + ')')
            else:
                unenc_ts.append(x[name])

        if len(enc_ts) > 0:
            summary += 'Found ' + \
                       sing_plural(len(enc_ts), 'encrypted tablespace. ',
                                                'encrypted tablespaces. ')

        if len(unenc_ts) > 0:
            summary += 'Found ' + \
                       sing_plural(len(unenc_ts), 'unencrypted tablespace. ',
                                                'unencrypted tablespaces. ')
            details += 'Unencrypted tablespaces: ' + join_list(unenc_ts) + '\n'
            details += 'Encrypted tablespaces: ' + join_list(enc_ts) 

            details += '\n\n'
        else:
            summary += 'No unencrypted tablespaces found. '
            details += 'Encrypted tablespaces: ' + join_list(enc_ts)
            details += '\n\n'

    cdata = sat.get_data('encrypted_column', 1)
    enc_col = []
    if cdata is None:
        sat.diag('Skipped Encrypted Columns')
    else:
        owner = sat.get_index('encrypted_column', 'owner')
        tab_name = sat.get_index('encrypted_column', 'table_name')
        col_name = sat.get_index('encrypted_column', 'column_name')
        algo = sat.get_index('encrypted_column', 'encryption_alg')

        if len(cdata) > 0:
            summary += 'Found ' + \
                       sing_plural(len(cdata), 
                                   'encrypted column.', 'encrypted columns.')
            for x in cdata:
                enc_col.append('Column ' + x[col_name] + ' of ' + x[owner] + \
                               '.' + x[tab_name] + ' (' + x[algo] + ')')
            details += 'Encrypted columns: ' + join_list(enc_col) + '\n\n'
        else:
            summary += 'No encrypted columns found.'

    if tdata is None and cdata is None and wdata is None:
        return

    checked, num_issues, param_details = \
       param_should('ENCRYPT_NEW_TABLESPACES', 'ALWAYS')
    if num_issues == 1:
        param_details = param_details[:-2] + ' in the Oracle Cloud or in ' + \
                        'an on-premise database.\n'
    if checked == 0:
        if target_db_version >= '12.2':
            sat.diag('Skipped ENCRYPT_NEW_TABLESPACES Parameter Check')
    else:
        summary += ' Examined ' + \
                   sing_plural(checked, 'initialization parameter.',
                                        'initialization parameters.')
        details += param_details

    cs_data = sat.get_data('cloud_service',1)
    cs_idx = sat.get_index('cloud_service','cs')
    is_cs = 0
    if cs_data is not None:
         is_cs = cs_data[0][cs_idx];


    if (len(enc_ts) + len(enc_col)) == 0:
        severity = sat.SEV_ENHANCEMENT
    else:
        if checked > 0 and num_issues > 0:
            severity = sat.SEV_ENHANCEMENT
        else:
            severity = sat.SEV_UNKNOWN

    if is_cs > 0 and len(unenc_ts) > 0:
        severity = sat.SEV_MEDIUM

#    remarks = 'Encryption of sensitive data is a requirement ' + \
#        'in most regulated environments. ' + \
#        'Transparent Data Encryption automatically encrypts ' + \
#        'data as it is stored and decrypts it upon retrieval. ' + \
#        'This protects sensitive data from attacks that bypass ' + \
#        'the database and read data files directly. ' + \
#        'Encryption keys may be stored in wallets on the database ' + \
#        'server itself, or stored remotely in Oracle Key Vault for ' + \
#        'improved security. '
    remarks = '個人情報や機密情報の暗号化は、どの業種にも共通した必須のコンプライアンス要件です。' + \
       'Transparent Data Encryptionは、アプリケーションからは透過的に、格納されたデータを' + \
       '自動的に暗号化・復号します。これは、データベースをバイパスすることや直接データファイルを読むこと' + \
       'による攻撃から機密情報を保護します。暗号鍵は、一般的にはデータベースサーバー上のOracle Keystore(Wallet)に格納しますが、' + \
       'データベースサーバーとは別のOracle Key Vaultに格納することでよりセキュアに管理できます。'

    if checked > 0:
#        remarks += 'The ENCRYPT_NEW_TABLESPACES parameter ensures '     + \
#                   'that TDE tablespace encryption is applied to all '  + \
#                   'newly created tablespaces. Setting this parameter ' + \
#                   'to ALWAYS is recommended in order to protect all '  + \
#                   'data regardless of the options specified when the ' + \
#                   'tablespace is created.'
        remarks += 'ENCRYPT_NEW_TABLESPACES初期化パラメータを利用すると'     + \
                   '新しく作成した表領域をすべてTDE暗号化表領域として作成します。'  + \
                   '表領域作成時にオプションを指定することなくすべてのデータを保護できるため、' + \
                   'このパラメータをALWAYSに設定することが推奨されます。'
    refs = {'GDPR': 'Article 6, 32, 34; Recital 83', 
            'STIG': 'Rule SV-76157r2, SV-76245r2, SV-76251r1, SV-76261r2, ' + \
                    'SV-76263r3' }
#    sat.finding('Transparent Data Encryption', 'CRYPT.TDE', summary,
#        severity, details, remarks, refs)
    sat.finding('透過的データ暗号化'.decode('utf-8'), 'CRYPT.TDE', summary,
        severity, details, remarks.decode('utf-8'), refs)

def encryption_wallet():
    oh_dir = get_from_env_data('ORACLE_HOME')

    wdata = sat.get_data('encryption_wallet', 2)
    if oh_dir is None or wdata is None:
        sat.diag('Skipped Encryption Wallets')
        return

    db_file = sat.get_data('db_file_directory', 1)
    if db_file is not None:
        db_file_dir = sat.get_index('db_file_directory', 'value')
        for y in db_file:
           if y[db_file_dir] != '':
              oh_dir = y[db_file_dir] 

    type = sat.get_index('encryption_wallet', 'wrl_type')
    param = sat.get_index('encryption_wallet', 'wrl_parameter')
    status = sat.get_index('encryption_wallet', 'status')
    wtype = sat.get_index('encryption_wallet', 'wallet_type')
    order = sat.get_index('encryption_wallet', 'wallet_order')

    details = ''
    if len(wdata) > 0:
        summary = 'Found ' + sing_plural(len(wdata), 'wallet.', 'wallets.')
        for x in wdata:
            details += 'Encryption wallet location: ' + x[param] + '\n'
            details += 'Wallet type: ' + x[type] + '\n'
            details += 'Status: ' + x[status] + '\n'
            if wtype is not None:
               details += 'Keystore type: ' + x[wtype] + '\n'
            if order is not None:
               details += 'Wallet order: ' + x[order] + '\n'
            details += '\n'
    else:
        summary = 'No encryption wallets found.'

    if oh_dir[-1] != '/':
        oh_dir += '/'
    dbs_dir = oh_dir + 'dbs'

    details += 'Data file directory: %s\n' % dbs_dir
    wallets_with_dbs = []
    for x in wdata:
        if dbs_dir in x[param]:
            wallets_with_dbs.append(x[param])

    if len(wallets_with_dbs) > 0:
        severity = sat.SEV_MEDIUM
        summary += ' Found ' + sing_plural(len(wallet_with_dbs), 
                                           'wallet', 'wallets') + \
                   ' stored in the data file directory.'
        details += 'Wallets stored together with data files: \n'
        details += join_list(wallet_with_dbs, '\n')
    else:
        severity = sat.SEV_UNKNOWN
        summary += ' No wallets are stored in the data file directory.'

#    remarks = 'Wallets are encrypted files used to store encryption keys, ' + \
#        'passwords, and other sensitive data. Wallet files should not be '+ \
#        'stored in the same directory with database data files, to avoid ' + \
#        'accidentally creating backups that include both encrypted data ' + \
#        'files and the wallet containing the master key protecting those ' + \
#        'files. ' + \
#        'For maximum separation of keys and data, consider storing ' + \
#        'encryption keys in Oracle Key Vault instead of wallet files.'
    remarks = 'Oracle Keystore(Wallet)は、暗号鍵やパスワードを格納するために使用される暗号化された' + \
        'ファイルです。Oracle Keystoreファイルと暗号鍵の両方を含んだバックアップを誤って作成' + \
        'しないためにも、そのOracle Keystoreは、データベースのデータファイルと同じ場所に配置すべきではありません。' + \
        '暗号鍵とデータを最大限分離する方法は、Oracle Keystoreの代' + \
        'わりにOracle Key Vault内に暗号鍵を保管することです。'
    refs = {'GDPR': 'Article 6, 32, 34; Recital 83', 
            'STIG': 'Rule SV-76015r1, SV-76223r2, SV-76233r2'}

#    sat.finding('Encryption Key Wallet', 'CRYPT.WALLET', summary,
#        severity, details, remarks, refs)
    sat.finding('暗号鍵管理'.decode('utf-8'), 'CRYPT.WALLET', summary,
        severity, details, remarks.decode('utf-8'), refs)


def redaction():
    data = sat.get_data('redaction_policy', 1)
    if data is None:
        if target_db_version >= '12.1':
            sat.diag('Skipped Redaction Policies')
        return

    obj_owner = sat.get_index('redaction_policy', 'object_owner')
    obj_name = sat.get_index('redaction_policy', 'object_name')
    pol_name = sat.get_index('redaction_policy', 'policy_name')
    col_name = sat.get_index('redaction_policy', 'column_name')

    pol_list = [x[pol_name] for x in data]
    if len(pol_list) > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Found ' + \
                 sing_plural(len(set(pol_list)), 'Data Redaction policy', 
                                                 'Data Redaction policies') + \
                 ' protecting ' +  sing_plural(len(data), 'object.', 'objects.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No data is being dynamically redacted.'

    dict = {}
    for x in data:
        str = x[obj_owner] + '.' + x[obj_name] + ' (col ' + x[col_name] + ')'
        if x[pol_name] in dict:
            dict.get(x[pol_name]).append(str)
        else:
            dict[x[pol_name]] = [str]

    details = ''
    for k, v in dict.items():
        details += 'Policy ' + k + ': Protects ' + join_list(v) + '\n'

    exempt_privs = ['EXEMPT REDACTION POLICY']
    for p in exempt_privs:
        g_list, unique_users, num_admin = get_sys_priv_grantees(p)
        if g_list is not None:
            details += '\nUsers not impacted by Data Redaction Policies: ' 
            details += join_list(g_list)

    exec_users = get_execute_grantees('DBMS_REDACT')
    if exec_users is not None:
        details += '\nUsers who can create or manage Data Redaction Policies:  '
        details += join_list(exec_users)

#    remarks = 'Data Redaction automatically masks sensitive data found ' + \
#        'in the results of a database query. The data is masked ' + \
#        'immediately before it is returned as part of the result ' + \
#        'set, so it does not interfere with any conditions ' + \
#        'specified as part of the query. ' + \
#        'Access by users with the EXEMPT REDACTION POLICY privilege ' + \
#        'will not be affected by the redaction policy. Users who can ' + \
#        'execute the DBMS_REDACT package are able to create and modify ' + \
#        'redaction policies. ' + \
#        'Also consider the use of Oracle Data Masking and Subsetting to ' + \
#        'permanently mask sensitive data when making copies for test ' + \
#        'or development use.'
    remarks = 'Data Redactionは、クエリー結果の中にある機密データを自動的にマスクします。クエリ' + \
        'ーの結果が返される直前にデータはマスクされるので、クエリ自身に含まれる条件に' + \
        'は影響を与えません。 EXEMPT REDACTION POLICY権限を持つユーザのアクセスは、リダク' + \
        'ションポリシーの影響を受けません。DBMS_REDACTパッケージの実行権限を持つユーザが' + \
        'リダクションポリシーの作成や修正を実行できます。同様に、Oracle Data Masking and Subset' + \
        'tingは、テストや開発環境向けに本番データをコピーし、永久的に機密データのマスクを' + \
        '行うことが可能です。'

    refs = {'GDPR': 'Article 6, 25, 32, 34, 89; Recital 28, 29, 78, 156'}

#    sat.finding('Data Redaction', 'ACCESS.REDACT', summary,
#        severity, details, remarks, refs)
    sat.finding('Data Redaction', 'ACCESS.REDACT', summary,
        severity, details, remarks.decode('utf-8'), refs)

def vpd_policy():
    data = sat.get_data('vpd_policy', 1)
    if data is None:
        sat.diag('Skipped VPD Policies')
        return
    data_col = sat.get_data('vpd_policy_columns', 1)

    pol_name = sat.get_index('vpd_policy', 'policy_name')
    pf_owner = sat.get_index('vpd_policy', 'pf_owner')
    pol_function = sat.get_index('vpd_policy', 'function')
    obj_owner = sat.get_index('vpd_policy', 'object_owner')
    obj_name = sat.get_index('vpd_policy', 'object_name')

    obj_col = sat.get_index('vpd_policy_columns', 'sec_rel_column')
    obj_col_owner = sat.get_index('vpd_policy_columns', 'object_owner')
    obj_col_name = sat.get_index('vpd_policy_columns', 'object_name')
    col_pol_name = sat.get_index('vpd_policy_columns', 'policy_name')

    pol_list = [x[pol_name] for x in data]
    if len(pol_list) > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Found ' + sing_plural(len(set(pol_list)), 
                                         'VPD policy', 'VPD policies') + \
                  ' protecting ' + sing_plural(len(data), 'object.', 'objects.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No VPD policies found that automatically limit access ' + \
                  'to certain rows and/or columns based upon the user or ' + \
                  'the database environment.'

    dict = {}
    for x in data:
        str = x[obj_owner] + '.' + x[obj_name]
        if data_col is not None:
           str_col = '('
           for y in data_col:
               if x[obj_owner] == y[obj_col_owner] and \
                  x[obj_name] == y[obj_col_name] and \
                  x[pol_name] == y[col_pol_name]:
                    if str_col == '(':
                        str_col = str_col + y[obj_col]
                    else:
                        str_col = str_col + ', ' + y[obj_col] 
           if str_col == '(':
              str_col = str_col + 'All'
           str = str + str_col + ')'
        if x[pol_name] in dict:
            dict.get(x[pol_name]).append(str)
        else:
            dict[x[pol_name]] = [str]


    details = ''
    if dict:
       details += 'Tables with VPD Enforcement: \n'
    for k, v in dict.items():
        details += 'Policy ' + k + ': Protects ' + join_list(v) + '\n'

    exempt_priv = 'EXEMPT ACCESS POLICY'
    g_list, unique_users, num_admin = get_sys_priv_grantees(exempt_priv)
    if g_list is not None:
        details += '\nUsers not impacted by VPD Policies: '
        details += join_list(g_list)

    exec_users = get_execute_grantees('DBMS_RLS')
    if exec_users is not None:
        details += '\nUsers who can create or manage VPD Policies: '
        details += join_list(exec_users)

#    remarks = 'Virtual Private Database (VPD) allows for fine-grained ' + \
#        'control over which rows and columns of a table are ' + \
#        'visible to a SQL statement. Access control using ' + \
#        'VPD limits each database session to only the specific ' + \
#        'data it should be able to access. ' + \
#        'Access by users with the EXEMPT ACCESS POLICY privilege ' + \
#        'will not be affected by VPD policies. Users who can ' + \
#        'execute the DBMS_RLS package are able to create and modify ' + \
#        'these policies.'
    remarks = '仮想プライベートデータベース(VPD）は、SQL文がテーブルの行と列を参照できるかどうかを' + \
        'きめ細かく制御することができます。VPDを使用したアクセス制御は、それぞれのセッションがアクセスで' + \
        'きるデータに従って制限されます。EXEMPT ACCESS POLICY権限を持つユーザーによるアク' + \
        'セスは、VPDポリシーによって影響を受けることはありません。DBMS_RLS権限を持つユー' + \
        'ザは、VPDポリシーを作成および変更することができます。'
    refs = {'GDPR': 'Article 29, 32'}

#    sat.finding('Virtual Private Database', 'ACCESS.VPD', summary,
#        severity, details, remarks, refs)
    sat.finding('仮想プライベートデータベース(VPD)'.decode('utf-8'), 'ACCESS.VPD', summary,
        severity, details, remarks.decode('utf-8'), refs)

def ras_policy():
    data = sat.get_data('ras_policy', 2)
    if data is None:
        if target_db_version >= '12.1':
            sat.diag('Skipped RAS Policies')
        return

    pol_owner = sat.get_index('ras_policy', 'policy_owner')
    pol_name = sat.get_index('ras_policy', 'policy_name')
    obj_owner = sat.get_index('ras_policy', 'schema')
    obj_name = sat.get_index('ras_policy', 'object')
    owner_bypass = sat.get_index('ras_policy', 'owner_bypass')

    pol_list = [x[pol_owner] + '.' + x[pol_name] for x in data]
    if len(pol_list) > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Found ' + sing_plural(len(set(pol_list)), 
                                         'RAS policy', 'RAS policies') + \
                  ' protecting ' + sing_plural(len(data), 'object.', 'objects.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No RAS policies found.'

    dict = {}

    for x in data:
        key = x[pol_owner] + '.' + x[pol_name]
        str = x[obj_owner] + '.' + x[obj_name]
        if x[owner_bypass]:
            str += ' (owner_bypass: Yes)'
        else:
            str += ' (owner_bypass: No)'
        if key in dict:
            dict.get(key).append(str)
        else:
            dict[key] = [str]

    details = ''
    for k, v in dict.items():
        details += 'Policy %s: Protects %s\n' % (k, join_list(v))

    details += '\n'
    exempt_priv = 'EXEMPT ACCESS POLICY'
    g_list, unique_users, num_admin = get_sys_priv_grantees(exempt_priv)
    if g_list is not None:
        details += 'Users not impacted by RAS Policies: %s\n' % \
                   (join_list(g_list))

    ras_priv_list = ['ADMIN_ANY_SEC_POLICY', 'ADMIN_SEC_POLICY', 
        'APPLY_SEC_POLICY']

    ras_list = []
    for ras_priv in ras_priv_list:
        g_list = get_ras_priv_grantees(ras_priv)
        if g_list is not None and len(g_list) > 0:
            ras_list += g_list

    details += 'Users who can create or manage RAS policies: %s\n' % \
               (join_list(sorted(ras_list)))

#    remarks = 'Like Virtual Private Database, Real Application ' + \
#        'Security (RAS) introduced in Oracle 12c Release 1, ' + \
#        'provides fine-grained control over the rows ' + \
#        'and columns of a table that are visible to a SQL ' + \
#        'statement. RAS data access policies ' + \
#        'uses a declarative syntax based on access control lists. ' + \
#        'Access by users with the EXEMPT ACCESS POLICY privilege ' + \
#        'will not be affected by RAS access policies. Users with ' + \
#        'ADMIN_SEC_POLICY and APPLY_SEC_POLICY privileges are able ' + \
#        'to create and modify these policies.'
    remarks = 'VPDのようにOracle 12cリリース1で導入されたReal Application Security (RAS)は、SQL文がテーブルの行と列を参照できるかどうかを' + \
        'きめ細かく制御することができます。RASデータアクセスポリシーは、アクセス制御リストに' + \
        '基づいた宣言構文を使用しています。 EXEMPT ACCESS POLICY権限を持つユーザーによる' + \
        'アクセスは、 RASアクセスポリシーによって影響を受けることはありません。 ADMIN_SEC' + \
        '_POLICYとAPPLY_SEC_POLICY権限を持つユーザーは、RASの作成および変更することができ' + \
        'ます。'
    refs = {'GDPR': 'Article 6, 25, 32, 34, 89; Recital 28, 29, 64, 78, 156'}

#    sat.finding('Real Application Security', 'ACCESS.RAS', summary,
#        severity, details, remarks, refs)
    sat.finding('Real Application Security', 'ACCESS.RAS', summary,
        severity, details, remarks.decode('utf-8'), refs)

def label_security():
    summary = ''
    details = ''

    if not db_options_dict.get('Oracle Label Security', False):
        severity = sat.SEV_ENHANCEMENT
        summary = 'Label Security is not enabled.'
        details = None
    else:
        severity = sat.SEV_UNKNOWN
        schema_pol_data = sat.get_data('ols_schema_policy', 1)
        table_pol_data = sat.get_data('ols_table_policy', 1)

        if schema_pol_data is None or table_pol_data is None:
            sat.diag('Skipped Label Security Checks')
            return
        else:
            pol_num = 0
            schema_pol_name = sat.get_index('ols_schema_policy', 'policy_name') 
            schema_name = sat.get_index('ols_schema_policy', 'schema_name')
            schema_pol_status = sat.get_index('ols_schema_policy', 'status')

            table_pol_name = sat.get_index('ols_table_policy', 'policy_name') 
            table_schema = sat.get_index('ols_table_policy', 'schema_name')
            table_name = sat.get_index('ols_table_policy', 'table_name')
            table_pol_status = sat.get_index('ols_table_policy', 'status')
    
            policy_dba_list = ['LBAC_DBA']       
            schema_pol_dict = {}
            for x in schema_pol_data: 
                if x[schema_pol_name] not in schema_pol_dict:
                    schema_pol_dict[x[schema_pol_name]] = []
                    pol_num += 1
                    policy_dba_list.append(x[schema_pol_name] + '_DBA')

                if x[schema_pol_status]:
                    schema_str  = x[schema_name] + ' (Enabled)'
                else:
                    schema_str  = x[schema_name] + ' (Disabled)'
                schema_pol_dict[x[schema_pol_name]].append(schema_str)

            for k, v in schema_pol_dict.items():
                details += 'Policy %s: Protects %s\n' % (k, join_list(v))

            table_pol_dict = {}
            for x in table_pol_data:
                if x[table_pol_name] not in schema_pol_dict:
                    pol_num += 1
                    policy_dba_list.append(x[table_pol_name] + '_DBA')
                    if x[table_pol_name] not in table_pol_dict:
                        table_pol_dict[x[table_pol_name]] = []

                    if x[table_pol_status]:
                        table_str  = x[table_schema] + '.' + \
                                     x[table_name] + ' (Enabled)'
                    else:
                        table_str  = x[table_schema] + '.' + \
                                     x[table_name] + ' (Disabled)'
                    table_pol_dict[x[table_pol_name]].append(table_str)

            for k, v in table_pol_dict.items():
                details += 'Policy %s: Protects %s\n' % (k, join_list(v))

            if len(schema_pol_data) == 0 and len(table_pol_data) == 0:
                severity = sat.SEV_ENHANCEMENT
                summary = 'No Label Security policies found.'
            else:
                severity = sat.SEV_UNKNOWN
                summary = 'Found ' + \
                          sing_plural(pol_num, 'Label Security policy', 
                                               'Label Security policies') + \
                          ' protecting ' + \
                          sing_plural(len(schema_pol_data), 
                                      'schema', 'schemas') + \
                          ' and ' + \
                          sing_plural(len(table_pol_data), 'table.', 'tables.')                                                         
            role_grants = sat.get_data('role_grants', 0)
            if role_grants is None or all_roles is None:
                sat.diag('Skipped Label Security roles grant info')
            else:
                r_grantee = sat.get_index('role_grants', 'grantee')
                r_role = sat.get_index('role_grants', 'granted_role')
                r_common = sat.get_index('role_grants', 'common')

                details += '\n'
                for p_admin in sorted(policy_dba_list): 
                    if con_type == 'PDB':
                       owners = get_local_role_grantees(p_admin, role_grants, 
                                                  r_grantee, r_role, r_common)
                    else:
                       owners = get_role_grantees(p_admin, role_grants,
                                                  r_grantee, r_role)
                    details += 'Users with %s role: %s\n' % \
                               (p_admin, join_list(owners))

            exempt_priv = 'EXEMPT ACCESS POLICY'
            g_list, unique_users, num_admin = get_sys_priv_grantees(exempt_priv)

            if g_list is not None:
                details += 'Users with ' + exempt_priv + ' privilege: '
                details += join_list(g_list)

#    remarks = "Oracle Label Security uses row level data classifications " + \
#        "to enforce access controls restricting users to only the data " + \
#        "they are allowed to access. Access to " \
#        "sensitive data is controlled by comparing the data label with " \
#        "the requesting user's label or security clearance. A user " \
#        "label or security clearance can be thought of as an extension to " \
#        "standard database privileges and roles. " + \
#        "Access by users with the EXEMPT ACCESS POLICY privilege " + \
#        "will not be affected by the Label Security policies. " + \
#        "Each policy has a corresponding role; users who have this role " + \
#        "are able to administer the policy."
    remarks ='Oracle Label Securityは、行レベルのデータ分類を使用して、許可されたデータにのみアクセスできるように' + \
            'ユーザーを制限するアクセス制御を実施します。機密データへのアクセスは、要求しているユーザーのラベルやセキュリテ' + \
            'ィクリアランスとのデータラベルを比較することによって制御されています。ユーザーの' + \
            'ラベルやセキュリティクリアランスが標準的なデータベースの権限とロールの拡張として' + \
            '考えることができます。 EXEMPT ACCESS POLICY権限を持つユーザーによるアクセスは、 ' + \
            'Label Securityポリシーの影響を受けません。各ポリシーには、対応するロールがあり、' + \
            'このロールを持つユーザーは、ポリシーを管理することができます。'
    refs = {'GDPR': 'Article 18, 29, 32; Recital 67'}

#    sat.finding('Label Security', 'ACCESS.OLS', summary,
#        severity, details, remarks, refs)
    sat.finding('Label Security', 'ACCESS.OLS', summary,
        severity, details, remarks.decode('utf-8'), refs)

def tsdp_policy():
    data_type_col = sat.get_data('tsdp_sensitive_type_col', 1)
    data_policy = sat.get_data('tsdp_policy', 1)

    if data_type_col is None or data_policy is None:
        if target_db_version >= '12.1':
            sat.diag('Skipped TSDP Policies')
        return

    severity = sat.SEV_UNKNOWN
    summary = ''
    details = ''

    if len(data_type_col) == 0 or len(data_policy) == 0:
        severity = sat.SEV_ENHANCEMENT

    if data_type_col is not None:
        type = sat.get_index('tsdp_sensitive_type_col', 'sensitive_type')
        owner = sat.get_index('tsdp_sensitive_type_col', 'schema_name')
        tab = sat.get_index('tsdp_sensitive_type_col', 'table_name')
        col = sat.get_index('tsdp_sensitive_type_col', 'column_name')
        
        if len(data_type_col) > 0:
            type_list = [x[type] for x in data_type_col]
            summary = 'Found ' + \
                      sing_plural(len(set(type_list)), 'sensitive type',
                                                       'sensitive types') + \
                      ' and ' + \
                      sing_plural(len(data_type_col), 'associated sensitive column.',
                                                      'associated sensitive columns.')
            tc_list = []
            for t in type_list:
                cols = []
                for x in data_type_col:
                    if x[type] == t:
                        cols.append('Col ' + x[col] + ' of ' + x[owner] + \
                                    '.' + x[tab])
                if len(cols) > 0:
                    tc_list.append(t + ' (' + join_list(cols) + ')')
                else:
                    tc_list.append(t)

            details += 'Sensitive types and associated sensitive columns: ' + join_list(tc_list)
            details += '\n\n'
        else:
            summary = 'No data tagged with sensitive types found. '

    if data_policy:
        policy = sat.get_index('tsdp_policy', 'policy_name')
        feature = sat.get_index('tsdp_policy', 'security_feature')

        p_list = [x[policy] + ' (' + x[feature] + ')' for x in data_policy \
                  if x[policy] != 'REDACT_AUDIT']
        summary += ' Found ' + sing_plural(len(p_list), 'TSDP policy.', 
                                                        'TSDP policies.')
        details += 'Policies: ' + join_list(p_list)
    else:
        summary = ' No TSDP policies found.'

    exec_users = get_execute_grantees('DBMS_TSDP_MANAGE')
    if exec_users is not None:
        details += '\n\nUsers with EXECUTE on SYS.DBMS_TSDP_MANAGE: '
        details += join_list(exec_users)

    exec_users = get_execute_grantees('DBMS_TSDP_PROTECT')
    if exec_users is not None:
        details += '\nUsers with EXECUTE on SYS.DBMS_TSDP_PROTECT: '
        details += join_list(exec_users)

#    remarks = 'Transparent Sensitive Data Protection (TSDP), introduced in ' + \
#        'Oracle Database 12c Release 1 Enterprise Edition, ' + \
#        'allows a data type(such as Credit Card number) to be ' + \
#        'associated with each column that contains sensitive ' + \
#        'data. TSDP can then apply various data security ' + \
#        'features such as Data Redaction or Virtual Private Database ' + \
#        'to all instances of that particular type so that ' + \
#        'protection is uniform and consistent. ' + \
#        'Data from columns marked as sensitive is also automatically ' + \
#        'redacted in the database audit trail and trace logs. ' + \
#        'Users who can execute the DBMS_TSDP_MANAGE and DBMS_TSDP_PROTECT ' + \
#        'packages are able to manage sensitive data types and the ' + \
#        'protection actions that are applied to them.'
    remarks = 'Oracle Database 12cリリース1 Enterprise Edition で導入された透過的な機密データの保護（TSDP）は、' + \
        'データタイプ(例えば、クレジットカード番号)を機密データを含む各列と関連付けることができます。TSDPを利用することで' + \
        'その特定のデータタイプに対して Data Redaction や Virtual Private Database などのさまざまなセキュリティ機能をすべての' + \
        'インスタンス上で適用し、均一で一貫した保護を実現します。機密としてマークされた列は、監査ログやトレースで' + \
        '自動的にリダクションされ記録されます。DBMS_TSDP_MANAGEとDBMS_TSDP_PROTECT権限' + \
        'をもつユーザは、機密データのタイプと、それらに適用される保護のアクションを管理す' + \
        'ることができます。'
#    sat.finding('Transparent Sensitive Data Protection (TSDP)',
#        'ACCESS.TSDP', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('Transparent Sensitive Data Protection (TSDP)',
        'ACCESS.TSDP', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))

def get_ras_priv_grantees(priv):
    ras_privs = sat.get_data('ras_privs', 1)
    role_grants = sat.get_data('role_grants', 0)

    if ras_privs is None or role_grants is None or all_roles is None:
        sat.diag('Skipped Get RAS Privilege Grantees')
        return None

    ras_grantee = sat.get_index('ras_privs', 'principal')
    ras_priv = sat.get_index('ras_privs', 'privilege')
    r_grantee = sat.get_index('role_grants', 'grantee')
    r_role = sat.get_index('role_grants', 'granted_role')
    r_common = sat.get_index('role_grants', 'common')

    users = set()
    for x in ras_privs:
        if x[ras_priv] == priv:
            grantee = x[ras_grantee]
            if grantee in all_roles:
                if con_type == 'PDB':
                   for u in get_local_role_grantees(grantee, role_grants, 
                   r_grantee, r_role, r_common):
                       users = users.union(set([u]))
                else:
                   for u in get_role_grantees(grantee, role_grants,  
                   r_grantee, r_role):
                       users = users.union(set([u]))
            else:
                users = users.union(set([grantee]))

    return sorted(list(users))


def audit_trail():
    nonempty = 0
    trails_checked = 0
    details =''
    if pure_unified_audit == 'Yes': 
      audit_trails = (('fine_grained_audit_trail', 'FGA Audit Trail'),
                      ('unified_audit_trail_stats', 'Unified Audit Trail'))
    else:
     audit_trails = (('traditional_audit_trail', 'Traditional Audit Trail'),
                      ('fine_grained_audit_trail', 'FGA Audit Trail'),
                      ('unified_audit_trail_stats', 'Unified Audit Trail'))

    for source, name in audit_trails:
        data = sat.get_data(source, 1)
        if data is None and source == 'unified_audit_trail_stats':
            source = 'unified_audit_trail'
            data = sat.get_data(source, 1)

        if data is not None:
            trails_checked += 1
            num_idx = sat.get_index(source, 'num')
            min_idx = sat.get_index(source, 'min_date')
            max_idx = sat.get_index(source, 'max_date')
            num_records = data[0][num_idx];

            if num_records == 0:
                details += name + ': No records found'
                if name == 'FGA Audit Trail':
                    data = sat.get_data('fine_grained_audit', 1)
                    if data is not None:
                        fga_enabled_cnt = 0
                        policy = sat.get_index('fine_grained_audit', 'policy_name')
                        pol_state = sat.get_index('fine_grained_audit', 'enabled');
                        pol_list = [x[policy] for x in data]
                        dict = {}
                        for x in data:
                            if x[policy] not in dict:
                                if x[pol_state]:
                                   fga_enabled_cnt += 1
                                   dict[x[policy]] = True
                        if len(pol_list) > 0:
                            details += '. Found ' + \
                            sing_plural(len(set(pol_list)),
                                         'fine grained audit policy, ',
                                         'fine grained audit policies, ')
                            details += '%d are enabled.' % (fga_enabled_cnt)
            else:
                nonempty += 1
                details += name + ': In use'
                if source != 'unified_audit_trail':
                    details += ', ' + \
                       sing_plural(num_records, 'record', 'records') + ' found'
                   
            if num_records > 0 and min_idx is not None and max_idx is not None:
                min_date = format_date(read_date(data[0][min_idx]), '%b %d %Y')
                max_date = format_date(read_date(data[0][max_idx]), '%b %d %Y')
                details += ' (' + min_date + ' - ' + max_date + ')'

            details += '\n'

    num_issues = 0
    param_checked = 0
    if traditional_audit == 'Yes':
      param_details = ''

      val = sys_param_dict.get('AUDIT_FILE_DEST')
      if val is not None:
          param_details = 'AUDIT_FILE_DEST=' + display_string(val) + '\n'

      val = sys_param_dict.get('AUDIT_SYSLOG_LEVEL')
      if val:
          param_details += 'AUDIT_SYSLOG_LEVEL=' + display_string(val) + '\n'
      else:
          param_details += 'AUDIT_SYSLOG_LEVEL is not set.\n'

      param_checked, num_issues, param_details = \
         param_should_not('AUDIT_TRAIL', 'NONE',
                          'OS, DB, DB,EXTENDED, XML, or XML,EXTENDED',
                          param_checked, num_issues, param_details)

      details += '\n' + param_details

    summary = 'Examined ' + \
              sing_plural(trails_checked, 'audit trail. ', 'audit trails. ')

    severity = sat.SEV_UNKNOWN
    if trails_checked > 0:
        if nonempty == 0:
            severity = sat.SEV_HIGH
            summary += 'Found no audit records. '
        else:
            summary += 'Found records in ' + \
                   sing_plural(nonempty, 'audit trail. ', 'audit trails. ')

    if param_checked:
        if num_issues > 0:
            summary += 'Found ' + sing_plural(num_issues, 'error', 'errors') + \
                       ' in audit initialization parameters.'
            if severity == sat.SEV_UNKNOWN:
                severity = sat.SEV_MEDIUM
        else:
            summary += 'No errors found in audit initialization parameters.'
        
#    remarks = 'Auditing is an essential component for monitoring the ' + \
#        'activities on any system including the ' + \
#        'activities of highly privileged users. ' + \
#        'Oracle Database 12c introduced Unified Auditing that centralizes ' + \
#        'audit logs in a single unified audit trail, and simplifies audit ' + \
#        'policy management, and is the ' + \
#        'recommended auditing mode moving forward. '+\
#        'The AUDIT_FILE_DEST controls the OS directory to which ' + \
#        'the audit trail is written if using AUDIT_TRAIL=os, xml, or ' + \
#        'xml,extended. This directory should be prevented from any '+\
#        'unauthorized access. ' + \
#        'Sending audit data to a remote system is recommended in order ' + \
#        'to prevent any possible local tampering with the audit records. ' + \
#        'The AUDIT_SYSLOG_LEVEL parameter can be set to send an ' + \
#        'abbreviated version of audit records to a remote syslog ' + \
#        'collector. A better solution is to use Oracle Audit Vault and ' + \
#        'Database Firewall to centrally collect full audit records from ' + \
#        'multiple databases.'
    remarks = '監査は、強い権限を持ったユーザーのアクティビティを含む、' + \
        'システム上のアクティビティを監視するための必要不可欠な要素です。' + \
		'Oracle Database 12cで導入された統合監査は、監査ログを単一の統合監査証跡に集中されて、' + \
		'監査ポリシーの管理を簡素化し、今後推奨される監査モードです。' + \
		'AUDIT_TRAILの値をOS、XMLまたはXML，EXTENDEDに設定することにより、' + \
		'監査証跡を設定します。AUDIT_FILE_DESTは、その監査証跡が書き込まれるOSディレクトリを制御します。' + \
		'このディレクトリへの不正アクセスを防止する必要があります。' + \
        'データベースから別のシステムに監査データを送信することが、監査レコードのローカル改ざんのあらゆる' + \
        '可能性を防ぐために推奨されます。 AUDIT_SYSLOG_LEVELパラメータは、リモートsyslog' + \
        'サーバに監査レコードの省略された値を送信するように設定できます。よりよい解決策は、' + \
        'Oracle Audit Vault and Database Firewallに様々なデータベースの監査レコードを送信' + \
        'して一元管理することです。'
    refs = {'CIS': 'Recommendation 2.2.2', 'GDPR': 'Article 30, 33, 34',
            'STIG': 'Rule SV-75899r1, SV-76111r1, SV-76117r1, SV-76121r1, ' + 
             'SV-76123r1, SV-76125r1, SV-76127r1, SV-76129r1, SV-76455r3'}
#    sat.finding('Audit Records', 'AUDIT.RECORDS', summary,
#        severity, details, remarks, refs)
    sat.finding('監査レコード'.decode('utf-8'), 'AUDIT.RECORDS', summary,
        severity, details, remarks.decode('utf-8'), refs)


def statement_audit():
    tdata = sat.get_data('statement_audit', 1)
    if target_db_version >= '12.2':
        udata = sat.get_data('unified_audit_details', 3)
    else:
        udata = sat.get_data('unified_audit_details', 1)

    if tdata is None and udata is None:
        sat.diag('Skipped Statement Audit')
        return

    t_list = []
    if tdata is not None and traditional_audit == 'Yes':
        opt = sat.get_index('statement_audit', 'audit_option')
        t_list = [t[opt] for t in tdata]
        t_list = list(set(t_list))

    u_list = []
    if udata is not None:
        ty = sat.get_index('unified_audit_details', 'audit_option_type')
        opt = sat.get_index('unified_audit_details', 'audit_option')
        u_list = [u[opt] for u in udata if u[ty] == 'STANDARD ACTION']
        u_list = list(set(u_list))

    details = ''

    if len(t_list) > 0:
        details += 'Traditional Audit (%d): ' % len(t_list)
        details += join_list(sorted(t_list)) + '\n'

    if len(u_list) > 0:
        if len(t_list) > 0:
            details += '\n'
        details += 'Unified Audit (%d): ' % len(u_list)
        details += join_list(sorted(u_list))

    total = len(t_list) + len(u_list)

    if total > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Auditing enabled for ' + \
                  sing_plural(total, 'statement.', 'statements.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No auditing enabled for statements.'
        details = None

#    remarks = 'This finding shows the SQL statements that are audited ' + \
#        'by enabled audit policies. It is recommended that SQL statements ' + \
#        'like GRANT DIRECTORY and LOCK TABLE are audited.'
    remarks = 'この結果は、SQL文を対象に有効化された監査ポリシーを表わしています。' + \
		'GRANT DIRECTORYやLOCK TABLEなどのSQL文を監査することをお勧めします。'

#    sat.finding('Statement Audit', 'AUDIT.STMT', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('ステートメント監査'.decode('utf-8'), 'AUDIT.STMT', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))


def object_audit():
    if traditional_audit == 'Yes':       
       tdata = sat.get_data('object_audit', 1)
    else:
       tdata = None
    if target_db_version >= '12.2':
        udata = sat.get_data('unified_audit_details', 3)
    else:
        udata = sat.get_data('unified_audit_details', 1)

    if tdata is None and udata is None:
        sat.diag('Skipped Object Audit')
        return

    t_dict = {}
    if tdata is not None:
        owner = sat.get_index('object_audit', 'owner')
        name = sat.get_index('object_audit', 'object_name')

        for x in tdata:
            if x[owner] in t_dict.keys():
                if x[name] not in t_dict[x[owner]]:
                    t_dict[x[owner]].append(x[name])
            else:
                t_dict[x[owner]] = []
                t_dict[x[owner]].append(x[name])

    u_dict = {}
    if udata is not None:
        ty = sat.get_index('unified_audit_details', 'audit_option_type')
        owner = sat.get_index('unified_audit_details', 'object_schema')
        name = sat.get_index('unified_audit_details', 'object_name')

        for x in udata:
            if x[ty] != 'OBJECT ACTION':
                continue
            if x[owner] in u_dict.keys():
                if x[name] not in u_dict[x[owner]]:
                    u_dict[x[owner]].append(x[name])
            else:
                u_dict[x[owner]] = []
                u_dict[x[owner]].append(x[name])

    details = ''
    total = 0

    if len(t_dict) > 0:
        details += 'Traditional Audit:\n'
        for x in sorted(t_dict.keys()):
            objs = t_dict[x]
            num = len(objs)
            total += num
            details += 'Schema %s (%d): %s\n' % (x, num, join_list(objs))

    if len(u_dict) > 0:
        if len(t_dict) > 0:
            details += '\n'
        details += 'Unified Audit:\n'
        for x in sorted(u_dict.keys()):
            objs = u_dict[x]
            num = len(objs)
            total += num
            details += 'Schema %s (%d): %s\n' % (x, num, join_list(objs))

    if total > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Auditing enabled for ' + \
                  sing_plural(total, 'object.', 'objects.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No auditing enabled for objects.'
        details = None

#    remarks = 'This finding shows the object accesses that are audited ' + \
#        'by enabled audit policies.'
    remarks = 'この結果は、オブジェクトへのアクセスを対象に有効化された監査ポリシーを表わしています。'

    refs = {'STIG': 'Rule SV-76141r1'}

#    sat.finding('Object Audit', 'AUDIT.OBJ', summary,
#        severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('オブジェクト監査'.decode('utf-8'), 'AUDIT.OBJ', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def privilege_audit():
    tdata = sat.get_data('privilege_audit', 1)
    if target_db_version >= '12.2':
        udata = sat.get_data('unified_audit_details', 3)
    else:
        udata = sat.get_data('unified_audit_details', 1)

    if tdata is None and udata is None:
        sat.diag('Skipped Privilege Audit')
        return

    t_list = []
    if tdata is not None and traditional_audit == 'Yes':
        priv = sat.get_index('privilege_audit', 'privilege')
        t_list = [t[priv] for t in tdata]
        t_list = sorted(list(set(t_list)))

    u_list = []
    if udata is not None:
        ty = sat.get_index('unified_audit_details', 'audit_option_type')
        opt = sat.get_index('unified_audit_details', 'audit_option')
        u_list = [u[opt] for u in udata if u[ty] == 'SYSTEM PRIVILEGE']
        u_list = sorted(list(set(u_list)))

    details = ''

    if len(t_list) > 0:
        details += 'Traditional Audit (%d): ' % len(t_list)
        details += join_list(t_list) + '\n'

    if len(u_list) > 0:
        if len(t_list) > 0:
            details += '\n'
        details += 'Unified Audit (%d): ' % len(u_list)
        details += join_list(u_list)

    total = len(t_list) + len(u_list)
    if total > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Auditing enabled for ' + \
                  sing_plural(total, 'privilege.', 'privileges.')
    else:
        severity = sat.SEV_MEDIUM
        summary = 'Use of privilege management privileges are not fully audited.'
        details = None

#    remarks = 'This finding shows the privileges that are audited ' + \
#        'by enabled audit policies. It is recommended that privileges such ' + \
#        'as GRANT ANY OBJECT PRIVILEGE, GRANT ANY PRIVILEGE and ' + \
#        'DROP ANY PROCEDURE are audited.'
    remarks = 'この結果は、権限を対象に有効化された監査ポリシーを表わしています。' + \
		'GRANT ANY OBJECT PRIVILEGE、GRANT ANY PRIVILEGE、DROP ANY PROCEDUREなどの権限を監査することをお勧めします。'
    refs = {'CIS': 'Recommendation 5.1.15, 5.1.16, 5.1.17'}

#    sat.finding('Privilege Audit', 'AUDIT.PRIV', summary,
#        severity, details, remarks, refs)
    sat.finding('権限監査'.decode('utf-8'), 'AUDIT.PRIV', summary,
        severity, details, remarks.decode('utf-8'), refs)

def check_admin_audit():
    if target_db_version >= '12.2':
        udata = sat.get_data('unified_audit_details', 3)
    else:
        udata = sat.get_data('unified_audit_details', 2)
    if not sys_param_dict and udata is None:
        sat.diag('Skipped Administrative User Audit')
        return

    details = ''

    t_sys_audit = None
    if traditional_audit == 'Yes':
       if sys_param_dict:
          val = sys_param_dict.get('AUDIT_SYS_OPERATIONS').upper()
          details = \
                'Traditional Audit: AUDIT_SYS_OPERATIONS is set to %s.\n\n' % val

          t_sys_audit = (val == 'TRUE')

    u_sys_audit = False
    if udata is not None:
        uname = sat.get_index('unified_audit_details', 'user_name')
        pname = sat.get_index('unified_audit_details', 'policy_name')
        dict = {}

        for x in udata:
            if x[uname] in oracle_admin_users:
                if x[uname] == 'SYS':
                    u_sys_audit = True
                if x[uname] in dict:
                    dict.get(x[uname]).append(x[pname])
                else:
                    dict[x[uname]] = [x[pname]]

        details += 'Unified Audit policies enabled for administrators: '
        pol_list = []
        for  k, v in dict.items():
            pol_list.append(k + ' (' + join_list(sorted(list(set(v)))) + ')')
        details += join_list(pol_list)

    if u_sys_audit or (traditional_audit == 'Yes' and t_sys_audit):
        summary = 'Actions of the SYS user are audited.'
        severity = sat.SEV_OK
    else:
        summary = 'Actions of the SYS user are not audited.'
        severity = sat.SEV_MEDIUM

#    remarks = 'It is important to audit administrative actions performed ' + \
#        'by the SYS user. Traditional audit policies do not apply to ' + \
#        'SYS, so the AUDIT_SYS_OPERATIONS parameter must be set to ' + \
#        'record SYS actions to a separate audit trail. Beginning with ' + \
#        'Oracle 12c, the same Unified Audit policies can be applied to ' + \
#        'SYS that are used to monitor other users.'
    remarks = 'SYSユーザーによって実行される管理操作を監査することは重要です。 従来の監査設定は' + \
        'SYSユーザには適用されないので、AUDIT_SYS_OPERATIONSパラメータをTRUEにして別々の' + \
        '監査証跡にSYSアクションを記録するように設定しなければなりません。Oracle 12cから' + \
        'のUnified Auditポリシーは、他のユーザを監視するために設定したポリシーはSYS' + \
        'ユーザにも同様に適用されます。'
    refs = {'CIS': 'Recommendation 2.2.1',
            'STIG': 'SV-75983r1, Rule SV-76009r1, SV-76085r2'}

#    sat.finding('Audit Administrative (SYS*) Users', 'AUDIT.ADMIN', summary,
#        severity, details, remarks, refs)
    sat.finding('管理者(SYS*)ユーザ監査'.decode('utf-8'), 'AUDIT.ADMIN', summary,
        severity, details, remarks.decode('utf-8'), refs)

def check_audited_grant_stmt():
    role_privs = set(['CREATE ROLE', 'ALTER ROLE', 'DROP ROLE'])
    sys_grant_privs = set(['GRANT ANY ROLE', 'GRANT ANY PRIVILEGE'])
    grant_privs = sys_grant_privs.union(set(['GRANT ANY OBJECT PRIVILEGE']))
    privmgmt_privs = role_privs.union(grant_privs)

    t_audits = check_traditional_audit(privmgmt_privs)
    u_audits = check_unified_audit(privmgmt_privs)

    if t_audits is None and u_audits is None:
        sat.diag('Skipped Privilege Management Audit Check')
        return

    uncovered = grant_privs.difference(set_union([t_audits, u_audits]))

    uncovered, t_audits = check_audit_shortcut(False, 'ROLE',
                                           role_privs, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'SYSTEM GRANT',
                                           sys_grant_privs, uncovered, t_audits)

    grant_revoke = set(['GRANT', 'REVOKE'])
    uset = check_unified_audit(grant_revoke)
    if uset is not None:
        u_audits = u_audits.union(uset)
        if grant_revoke.issubset(uset):
            uncovered = uncovered.difference(grant_privs)

    if len(uncovered) == 0:
        summary = 'Privilege management actions are fully audited.'
        severity = sat.SEV_OK
    else:
        summary = 'Privilege management actions are not fully audited.'
        severity = sat.SEV_MEDIUM

    details = get_audit_details(t_audits, u_audits, uncovered)

#    remarks = 'Granting additional privileges to users or roles ' + \
#        'potentially affects most security protection and ' + \
#        'should be audited. ' + \
#        'Each action or privilege listed here should be included in ' + \
#        'at least one enabled audit policy.'
    remarks = 'ユーザーまたはロールに追加の権限を付与することは、潜在的にほとんどのセキュリティ' + \
        '保護に影響を与えるため監査されるべきです。各アクション、またはここに記載されてい' + \
        'る権限は、少なくとも一つの有効化されている監査ポリシーに含まれるべきです。'
    refs = {'CIS': 'Recommendation 5.1.4, 5.1.5, 5.1.15, 5.1.16, 5.2.4 - 5.2.8'}

#    sat.finding('Privilege Management Audit', 'AUDIT.PRIVMGMT', summary,
#        severity, details, remarks, refs)
    sat.finding('権限管理監査'.decode('utf-8'), 'AUDIT.PRIVMGMT', summary,
        severity, details, remarks.decode('utf-8'), refs)

def check_audited_account_stmt():
    user_stmts = set(['CREATE USER', 'ALTER USER', 'DROP USER'])
    prof_stmts = set(['CREATE PROFILE', 'ALTER PROFILE', 'DROP PROFILE'])
    acct_stmts = user_stmts.union(prof_stmts)

    t_audits = check_traditional_audit(acct_stmts)
    u_audits = check_unified_audit(acct_stmts)

    if t_audits is None and u_audits is None:
        sat.diag('Skipped Account Management Audit Check')
        return

    uncovered = acct_stmts.difference(set_union([t_audits, u_audits]))

    uncovered, t_audits = check_audit_shortcut(False, 'USER', user_stmts, \
                                               uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'PROFILE', prof_stmts, \
                                               uncovered, t_audits)

    if len(uncovered) == 0:
        summary = 'Actions related to account management are ' \
                    'fully audited.'
        severity = sat.SEV_OK
    else:
        summary = 'Actions related to account management are ' \
                    'not fully audited.'
        severity = sat.SEV_MEDIUM

    details = get_audit_details(t_audits, u_audits, uncovered)

#    remarks = 'Creation of new user accounts or modification of ' + \
#        'existing accounts can be used to gain access to the ' + \
#        'privileges of those accounts and should be audited. ' + \
#        'Each action or privilege listed here should be included in ' + \
#        'at least one enabled audit policy.'
    remarks = '新しいユーザーアカウントまたは既存のアカウントの変更は、それらのアカウントの権限' + \
        'にアクセスを得るために使用することができるので、監査されるべきです。各アクション' + \
        'またはここに記載されている権限は、少なくとも現在有効となっている監査ポリシーに含' + \
        'まれているべきです。'
    refs = {'CIS': 
        'Recommendation 5.1.1, 5.1.2, 5.1.3, 5.1.6, 5.1.7, 5.1.8, ' +
        '5.2.1, 5.2.2, 5.2.3, 5.2.9, 5.2.10, 5.2.11',
        'STIG':'Rule SV-76055r2, SV-76059r2, SV-76061r4, SV-76063r2, ' + 
        'SV-76141r1, SV-76287r2, SV-76289r2, SV-76291r2, SV-76293r2'}

#    sat.finding('Account Management Audit', 'AUDIT.ACCTMGMT', summary,
#        severity, details, remarks, refs)
    sat.finding('アカウント管理監査'.decode('utf-8'), 'AUDIT.ACCTMGMT', summary,
        severity, details, remarks.decode('utf-8'), refs)

def check_audited_system_stmt():
    sys_stmts  = set(['ALTER SYSTEM', 'ALTER DATABASE',
                      'CREATE LIBRARY', 'CREATE ANY LIBRARY',
                      'SYSTEM AUDIT', 'CREATE EXTERNAL JOB', 'AUDIT ANY'])
    proc_stmts = set(['ALTER PROCEDURE', 'CREATE PROCEDURE', 'DROP PROCEDURE', 
                      'DROP ANY PROCEDURE'])
    pack_stmts = set(['ALTER PACKAGE', 'CREATE PACKAGE', 'DROP PACKAGE',
                      'CREATE PACKAGE BODY'])
    func_stmts = set(['ALTER FUNCTION', 'CREATE FUNCTION', 'DROP FUNCTION'])
    dir_stmts  = set(['CREATE ANY DIRECTORY', 'DROP ANY DIRECTORY'])
    psyn_stmts = set(['CREATE PUBLIC SYNONYM', 'DROP PUBLIC SYNONYM'])
    dbl_stmts  = set(['CREATE DATABASE LINK', 'ALTER DATABASE LINK',
                      'DROP DATABASE LINK'])
    pdbl_stmts = set(['CREATE PUBLIC DATABASE LINK',
                     'ALTER PUBLIC DATABASE LINK', 'DROP PUBLIC DATABASE LINK'])
    trig_stmts  = set(['CREATE TRIGGER', 'ALTER TRIGGER', 'DROP TRIGGER'])
    plug_stmts = set(['CREATE PLUGGABLE DATABASE', 'ALTER PLUGGABLE DATABASE',
                     'DROP PLUGGABLE DATABASE'])
    stmts_12   = set(['ADMINISTER KEY MANAGEMENT', 'CREATE SPFILE'])
    obj_aud    = set(['EXECUTE ON SYS.DBMS_RLS'])
    
    all_stmts = set_union([sys_stmts, proc_stmts, dir_stmts, psyn_stmts, 
        dbl_stmts, pdbl_stmts, trig_stmts, pack_stmts, func_stmts])
    if target_db_version >= '12':
        all_stmts = set_union([all_stmts, plug_stmts, stmts_12])

    t_audits = check_traditional_audit(all_stmts)
    u_audits = check_unified_audit(all_stmts)

    if t_audits is None and u_audits is None:
        sat.diag('Skipped Database Management Audit Check')

    uncovered = all_stmts.difference(set_union([t_audits, u_audits]))

    tset = check_traditional_audit(obj_aud, True)
    if tset is not None:
        t_audits = t_audits.union(tset)
    uset = check_unified_audit(obj_aud, True)
    if uset is not None:
        u_audits = u_audits.union(uset)

    uncovered_obj = obj_aud.difference(set_union([tset, uset]))
    uncovered = uncovered.union(uncovered_obj)

    uncovered, t_audits = check_audit_shortcut(False, 'DIRECTORY', dir_stmts,
                                               uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'PUBLIC SYNONYM',
                                               psyn_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'DATABASE LINK',
                                               dbl_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'PUBLIC DATABASE LINK',
                                               pdbl_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'PLUGGABLE DATABASE',
                                               plug_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'TRIGGER',
                                               trig_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'PROCEDURE', 
                                               proc_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'PACKAGE',
                                               pack_stmts, uncovered, t_audits)

    uncovered, t_audits = check_audit_shortcut(False, 'FUNCTION',
                                               func_stmts, uncovered, t_audits)


    if len(uncovered) == 0:
        summary = 'Actions related to database management are ' \
                  'fully audited.'
        severity = sat.SEV_OK
    else:
        summary = 'Actions related to database management are not ' \
                  'fully audited.'
        severity = sat.SEV_MEDIUM

    details = get_audit_details(t_audits, u_audits, uncovered)

#    remarks = 'Actions that affect the management of ' + \
#        'database features should always be audited. ' + \
#        'Each action or privilege listed here should be included in ' + \
#        'at least one enabled audit policy.'
    remarks = 'データベース管理に影響を与えるアクションは、監査されるべきです。各アクションまた' + \
        'はここに記載されている権限は、少なくとも現在有効となっている監査ポリシーに含まれ' + \
        'ているべきです。'
    refs = {'CIS': 'Recommendation 5.1.9, 5.1.10, 5.1.11, 5.1.17, ' +
        '5.1.19 - 5.1.21, 5.2.12 - 5.2.14, 5.2.20 - 5.2.26', 
        'STIG': 'Rule SV-83467r1'}

#    sat.finding('Database Management Audit', 'AUDIT.DBMGMT',
#        summary, severity, details, remarks, refs)
    sat.finding('データベース管理監査'.decode('utf-8'), 'AUDIT.DBMGMT',
        summary, severity, details, remarks.decode('utf-8'), refs)

def check_audited_privs_usage():
    privs    = set(['EXEMPT ACCESS POLICY', 'CREATE ANY TRIGGER',
                   'SELECT ANY DICTIONARY',
                   'CREATE ANY JOB', 'CREATE ANY PROCEDURE', 'BECOME USER'])
    priv_112 = set(['EXEMPT REDACTION POLICY'])
    privs_12 = set(['LOGMINING', 'CREATE ANY SQL TRANSLATION PROFILE',
                    'ALTER ANY SQL TRANSLATION PROFILE', 'TRANSLATE ANY SQL'])

    if target_db_version >= '11.2':
        privs = privs.union(priv_112)

    if target_db_version >= '12':
        privs = privs.union(privs_12)

    t_audits = check_traditional_audit(privs)
    u_audits = check_unified_audit(privs)

    if t_audits is None and u_audits is None:
        sat.diag('Skipped Privilege Usage Audit Check')

    uncovered = privs.difference(set_union([t_audits, u_audits]))

    details = get_audit_details(t_audits, u_audits, uncovered)
    if len(uncovered) == 0:
        summary = 'Usages of powerful system privileges are ' \
                  'fully audited.'
        severity = sat.SEV_OK
    else:
        summary = 'Usages of powerful system privileges are not ' \
                  'fully audited.'
        severity = sat.SEV_MEDIUM
        details = None

#    remarks = 'Usage of powerful system privileges should always ' + \
#        'be audited. Each privilege listed here should be included in ' + \
#        'at least one enabled audit policy.'
    remarks = '強力なシステム権限の使用は、監査されるべきです。。各アクションまたはここに記載さ' + \
        'れている権限は、少なくとも現在有効となっている監査ポリシーに含まれているべきです。'
    refs = {'CIS': 'Recommendation 5.1.14, 5.2.18'}

#    sat.finding('Privilege Usage Audit', 'AUDIT.PRIVUSE',
#        summary, severity, details, remarks, refs)
    sat.finding('強力な権限使用の監査'.decode('utf-8'), 'AUDIT.PRIVUSE',
        summary, severity, details, remarks.decode('utf-8'), refs)

def check_audited_connect_stmt():
    sess_priv = set(['LOGON', 'LOGOFF'])

    t_audits = set()
    t_audits = check_traditional_audit(sess_priv)
    u_audits = check_unified_audit(sess_priv)


    if t_audits is None and u_audits is None:
        sat.diag('Skipped Database Connection Audit Check')
        return

    uncovered = sess_priv.difference(set_union([t_audits, u_audits]))

    uncovered, t_audits = check_audit_shortcut(False, 'CREATE SESSION',
        sess_priv, uncovered, t_audits)

    if len(uncovered) == 0:
        summary = 'Database connections are fully audited.'
        severity = sat.SEV_OK
    else:
        summary = 'Database connections are not fully audited.'
        severity = sat.SEV_MEDIUM

    details = get_audit_details(t_audits, u_audits, uncovered)

#    remarks = "Successful user connections to the database should be " \
#        "audited to assist with forensic analysis. " \
#        "Unsuccessful connection attempts can provide early " \
#        "warning of an attacker's attempt to gain access to the " \
#        "database. Auditing the LOGOFF time helps understand how " \
#        "long the session was active, and is useful information " \
#        "for forensics."
    remarks = 'ユーザのデータベースへの接続成功は、電子情報のフォレンジックを手助けする' + \
        'ためにも監査されるべきです。接続試行の失敗は、データベースにアクセスする攻撃者' + \
        'の試みに早期警告を提供することができます。LOGOFF時間の監査は、' + \
        'セッションがアクティブであった時間を理解するのに役立ち、フォレンジックに役立つ情報です。'
    refs = {'CIS': 'Recommendation 5.1.22, 5.2.27',
            'STIG': 'Rule SV-76043r1, SV-76141r1, SV-76165r1' }

#    sat.finding('Audit User Logon / Logoff', 'AUDIT.CONN',
#        summary, severity, details, remarks, refs)
    sat.finding('ユーザー・ログオン/ログオフ監査'.decode('utf-8'), 'AUDIT.CONN',
        summary, severity, details, remarks.decode('utf-8'), refs)

def fine_grained_audit():
    data = sat.get_data('fine_grained_audit', 1)
    if data is None:
        sat.diag('Skipped Fine-Grained Audit')
        return

    policy = sat.get_index('fine_grained_audit', 'policy_name')
    obj_owner = sat.get_index('fine_grained_audit', 'object_schema')
    obj_name = sat.get_index('fine_grained_audit', 'object_name')
    col_name = sat.get_index('fine_grained_audit', 'policy_column')
    pol_state = sat.get_index('fine_grained_audit', 'enabled');
    details = ''

    pol_list = [x[policy] for x in data]
    if len(pol_list) > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Found ' + \
                  sing_plural(len(set(pol_list)), 'fine grained audit policy',
                                                  'fine grained audit policies')
        summary += ' for ' + sing_plural(len(data), 'object.', 'objects.')
    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No fine grained audit policies found.'

    dict = {}
    for x in data:
        if x[policy] in dict:
            dict[x[policy]] = dict.get(x[policy]) + ', ' + x[obj_owner] + \
                              '.' + x[obj_name] + ' (col ' + x[col_name] + ')'
        else:
            if x[pol_state]:
                str = '(Enabled): '
            else:
                str = '(Disabled): '
            str += 'Audits ' + x[obj_owner] + '.' + x[obj_name]
            str += ' (col ' + x[col_name] + ')'
            dict[x[policy]] = str 

    details = ''
    for k, v in dict.items():
        details += 'Policy %s %s\n' % (k, v)

    exec_users = get_execute_grantees('DBMS_FGA')
    if exec_users is not None:
        details += '\nUsers with EXECUTE on SYS.DBMS_FGA: '
        details += join_list(exec_users)

#    remarks = 'Fine Grained Audit policies can record specific ' + \
#        'activity, such as access to particular table with sensitive columns or ' + \
#        'access that occurs under specified conditions. This is ' + \
#        'an effective useful way to monitor unexpected data access while ' + \
#        'avoiding unnecessary audit records that correspond to ' + \
#        'normal activity.'
    remarks = 'ファイングレイン監査ポリシーは、機密列を含む表やセッション情報などの情報に基づいた特定の' + \
        'アクテビティに限定してログを記録します。これは正常なアクセスのログを不必要に記録' + \
        'することなく、予期しないデータへのアクセスのみを監視するのに効果的で便利な方法です。'

#    sat.finding('Fine Grained Audit', 'AUDIT.FGA', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('ファイングレイン監査'.decode('utf-8'), 'AUDIT.FGA', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))

def unified_audit_policy():
    data = sat.get_data('unified_audit_policy', 1)
    if data is None:
        if target_db_version >= '12.1':
            sat.diag('Skipped Unified Audit Policies')
        return

    policy = sat.get_index('unified_audit_policy', 'policy_name')
    state = sat.get_index('unified_audit_policy', 'state')
    num = sat.get_index('unified_audit_policy', 'num')


    data_details = sat.get_data('unified_audit_details', 1)
    uaud_details_op = sat.get_index('unified_audit_details', 'audit_option')
    uaud_details_obj_name = sat.get_index('unified_audit_details', 'object_name')
    uaud_details_obj_schema = sat.get_index('unified_audit_details', 'object_schema')
    uaud_details_policy = sat.get_index('unified_audit_policy', 'policy_name')


    if len(data) > 0:
        summary = 'Found ' + sing_plural(len(data), 'unified audit policy ',
                                                    'unified audit policies ')
        details = ''
        details_enabled = 'Enabled Policies: \n\n'
        details_disabled = 'Disabled Policies: \n\n'
        num_audits = 0
        policies_enabled = 0
        policies_disabled = 0

        for x in data:
            if x[state] == 'Enabled':
               details_enabled += x[policy]  + ': '
               details_enabled += 'Audits %d privileges/objects/statements' % x[num]
               policies_enabled += 1
               num_audits += x[num]
               if data_details is not None:
                   obj_audit_list = [y[uaud_details_op] + ' ON ' + y[uaud_details_obj_schema] + '.' + y[uaud_details_obj_name]
                         for y in data_details if y[uaud_details_policy] == x[policy] and y[uaud_details_obj_name] != 'NONE']
                   audit_list = [y[uaud_details_op] for y in data_details if y[uaud_details_policy] == x[policy]]
                   details_enabled += ' as follows: '
                   if len(audit_list) > 0:
                      details_enabled += join_list(sorted(audit_list))
                   if len(audit_list) > 0:
                      if len(obj_audit_list) <= 0:
                          details_enabled += '\n'
                      else :
                          details_enabled += ', '
                   if len(obj_audit_list) > 0:
                      details_enabled += join_list(obj_audit_list) + '\n'
               details_enabled += '\n'
            else:
               details_disabled += x[policy] + ': '
               details_disabled += 'Audits %d privileges/objects/statements' % x[num] + '\n'
               policies_disabled += 1
        if policies_enabled:
           details += details_enabled
        if policies_disabled:
           if policies_enabled:
              details += '\n'
           details += details_disabled

        if num_audits > 0:
            severity = sat.SEV_UNKNOWN
            summary += 'out of which ' + \
                       	sing_plural(policies_enabled, 'is enabled.',
                                               'are enabled.')
            summary += ' %d objects or statements being audited.' % num_audits + '\n'

        else:
            severity = sat.SEV_ENHANCEMENT
            summary += 'No unified audit policies are enabled.'

    else:
        severity = sat.SEV_ENHANCEMENT
        summary = 'No unified audit policies found.'
        details = None

#    remarks = 'Unified Audit, introduced in Oracle Database 12c, captures ' + \
#        'audit activity in one single unified audit trail. ' + \
#        'It also introduces new syntax ' + \
#        'for specifying effective audit policies including the ability to ' + \
#        'build conditions and add exclusions.'
    remarks = 'Oracle Database 12c で導入されたUnified Audit(統合監査)は、単一の統合された' + \
        '監査証跡で監査アクティビティをキャプチャします。また、条件構築や除外追加などの' + \
        '機能を含む効果的な監査ポリシーを指定するために新しい監査の構文が採用されています。'

    refs = {'STIG': 'Rule SV-76361r1', 'GDPR': 'Article 30, 33, 34'} 

#    sat.finding('Unified Audit Policies', 'AUDIT.UNIFIED', summary,
#            severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('統合監査(Unified Audit)ポリシー'.decode('utf-8'), 'AUDIT.UNIFIED', summary,
            severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def role_audit():
    if target_db_version >= '12.2':
        udata = sat.get_data('unified_audit_roles', 1)
    else:
        return
    if udata is None:
        sat.diag('Skipped Roles Audit')
        return
    rname = sat.get_index('unified_audit_roles', 'role_name')
    pname = sat.get_index('unified_audit_roles', 'policy_name')

    dict = {}
    num_pol = 0
    num_role = 0

    for x in udata:
         if x[rname] in dict:
              dict.get(x[rname]).append(x[pname])
              num_pol += 1
         else:
              dict[x[rname]] = [x[pname]]
              num_pol += 1
              num_role += 1
    details = ''
    if bool(dict):
        details += 'Roles for which Unified Audit policies are enabled: '
        pol_list = []
        for  k, v in dict.items():
            pol_list.append(k + ' (' + join_list(sorted(list(set(v)))) + ')')
        details += join_list(pol_list)


    if bool(dict):
       summary = 'Unified Audit Policies are enabled for %s.' % (sing_plural(num_role, 'role', 'roles'))
       severity = sat.SEV_UNKNOWN
    else:
       summary = 'No Audit Policy enabled on roles.'
       severity = sat.SEV_OK
       
#    remarks = 'When you audit a role, Oracle Database audits all system ' + \
#              'privileges that are directly granted to the role. ' + \
#              'Users granted these roles will be audited for the system ' + \
#              'privileges granted to the role.'
    remarks = 'ロールを監査すると、Oracle Databaseはロールに直接付与されている' + \
        'すべてのシステム権限を監査します。これらのロールを付与されたユーザーは、' + \
        'ロールに付与されたシステム権限について監査されます。'

#    sat.finding('Roles Audit', 'AUDIT.ROLE', summary,
#          severity, details, remarks)
    sat.finding('ロール監査'.decode('utf-8'), 'AUDIT.ROLE', summary,
          severity, details, remarks.decode('utf-8'))

def check_traditional_audit(aset, is_obj_audit=False):
  if traditional_audit == 'Yes' :
    if is_obj_audit:
        data = sat.get_data('object_audit', 1)
    else:
        data = sat.get_data('statement_audit', 1)

    if data is None or aset is None:
        return None

    if is_obj_audit:
        owner = sat.get_index('object_audit', 'owner')
        obj_name = sat.get_index('object_audit', 'object_name')
        sel = sat.get_index('object_audit', 'sel')
        upd = sat.get_index('object_audit', 'upd')
        ins = sat.get_index('object_audit', 'ins')
        dele = sat.get_index('object_audit', 'del')
        exe = sat.get_index('object_audit', 'exe')
        alt = sat.get_index('object_audit', 'alt')
        obj_aud_list = []
        not_audit = '-/-'
        for x in data:
            if x[sel] != not_audit:
                obj_aud_list.append('SELECT ON ' +
                                     x[owner] + '.' + x[obj_name])
            if x[upd] != not_audit:
                obj_aud_list.append('UDPATE ON ' +
                                     x[owner] + '.' + x[obj_name])
            if x[ins] != not_audit:
                obj_aud_list.append('INSERT ON ' +
                                     x[owner] + '.' + x[obj_name])
            if x[dele] != not_audit:
                obj_aud_list.append('DELETE ON ' +
                                     x[owner] + '.' + x[obj_name])
            if x[exe] != not_audit:
                obj_aud_list.append('EXECUTE ON ' +
                                     x[owner] + '.' + x[obj_name])
            if x[alt] != not_audit:
                obj_aud_list.append('ALTER ON ' +
                                     x[owner] + '.' + x[obj_name])
        result = set(obj_aud_list).intersection(aset)
    else:
        option = sat.get_index('statement_audit', 'audit_option')
        result = set([x[option] for x in data if x[option] in aset])

    return result

def check_unified_audit(aset, is_obj_audit=False):
    if target_db_version >= '12.2':
        data = sat.get_data('unified_audit_details', 3)
    else:
        data = sat.get_data('unified_audit_details', 1)
    if data is None or aset is None:
        return None

    op = sat.get_index('unified_audit_details', 'audit_option')
    if is_obj_audit:
        obj_name = sat.get_index('unified_audit_details', 'object_name')
        obj_schema = sat.get_index('unified_audit_details', 'object_schema') 
        audit_list = [x[op] + ' ON ' + x[obj_schema] + '.' + x[obj_name] 
                        for x in data]
    else:
        audit_list = [x[op] for x in data]
        if 'ALL' in audit_list:
            return aset

    return set(audit_list).intersection(aset)

def get_audit_details(tset, uset, uncovered):
    details = ''

    if uncovered:
        details += 'Auditing not enabled: ' + join_list(sorted(uncovered))
        details += '\n\n'

    if tset is not None and traditional_audit == 'Yes':
        if len(tset) == 0:
           details += 'Traditional audit - disabled.\n'
        else:
           details += 'Traditional audit - auditing enabled: ' 
           details += join_list(sorted(tset)) + '\n'

    if uset is not None:
        if len(uset) == 0:
           details += 'Unified audit - disabled.\n'
        else:
           details += 'Unified audit - auditing enabled: ' 
           details += join_list(sorted(uset)) + '\n'

    return details

def check_audit_shortcut(is_unified, shortcut, covering, uncovered, covered):
    if is_unified:
        aset = check_unified_audit(set([shortcut]))
    else:
        if traditional_audit == 'Yes':
           aset = check_traditional_audit(set([shortcut]))
        else:
           aset = None
    if aset is not None and shortcut in aset:
        uncovered = uncovered.difference(covering)
        covered = covered.union(aset)

    return uncovered, covered


def security_parameters():
    if not sys_param_dict:
        sat.diag('Skipped Security Parameters')
        return

    sec_params = set(('DBFIPS_140', 'O7_DICTIONARY_ACCESSIBILITY',
           'AUDIT_FILE_DEST', 'AUDIT_SYS_OPERATIONS',
           'AUDIT_SYSLOG_LEVEL', 'AUDIT_TRAIL',
           'CURSOR_BIND_CAPTURE_DESTINATION',
           'ENCRYPT_NEW_TABLESPACES', 'LDAP_DIRECTORY_ACCESS',
           'LDAP_DIRECTORY_SYSAUTH', 'OS_AUTHENT_PREFIX', 'OS_ROLES',
           'PDB_LOCKDOWN', 'PDB_OS_CREDENTIAL',
           'REMOTE_LOGIN_PASSWORDFILE',
           'REMOTE_OS_AUTHENT', 'REMOTE_OS_ROLES',
           'RESOURCE_LIMIT', 'SEC_CASE_SENSITIVE_LOGON',
           'SEC_MAX_FAILED_LOGIN_ATTEMPTS',
           'SEC_PROTOCOL_ERROR_FURTHER_ACTION',
           'SEC_PROTOCOL_ERROR_TRACE_ACTION',
           'SEC_RETURN_SERVER_RELEASE_BANNER', 'SQL92_SECURITY',
           'UNIFIED_AUDIT_SGA_QUEUE_SIZE', 'COMPATIBLE',
           'DISPATCHERS', 'GLOBAL_NAMES',
           'REMOTE_LISTENER', 'UTL_FILE_DIR', '_TRACE_FILES_PUBLIC',
           'UNIFIED_AUDIT_SYSTEMLOG', 'REMOTE_DEPENDENCIES_MODE',
           'OUTBOUND_DBLINK_PROTOCOLS', 'ADG_ACCOUNT_INFO_TRACKING'))

    rows = [[k, v] for k, v in sys_param_dict.items() if k in sec_params]

#    sat.table('Initialization Parameters for Security',
    sat.table('セキュリティ関連の初期化パラメータ'.decode('utf-8'),
                  [['Name', 'Value']] + sorted(rows), header=True)

def sec_parameter_checks():
    if not sys_param_dict:
        sat.diag('Skipped Security Parameter Checks')
        return

    access_parameter_checks()
    connection_parameter_checks()
    os_parameter_checks()
    utl_dir_parameter_check()

def access_parameter_checks():
    checked, num_issues, details = \
       param_should('O7_DICTIONARY_ACCESSIBILITY', 'FALSE')
    if num_issues > 0:
        summary = 'Dictionary objects can be accessed with ' + \
            'ANY TABLE privilege.'
        severity = sat.SEV_HIGH
    else:
        summary = 'Access to dictionary objects is properly limited.'
        severity = sat.SEV_OK
#    remarks = 'When O7_DICTIONARY_ACCESSIBILITY is set to FALSE, ' + \
#        'tables owned by SYS '+ \
#        'are not accessible through the ANY TABLE system privileges. ' + \
#        'This parameter should always be set to FALSE because ' + \
#        'tables owned by SYS control the overall state of the ' + \
#        'database and should not be subject to manipulation by ' + \
#        'users with ANY TABLE privileges.'
    remarks = 'O7_DICTIONARY_ACCESSIBILITYをFALSEに設定すると、 SYSが所有する表はANY TABLEシス' + \
        'テム権限からはアクセスできません。 SYSが所有する表は、データベースの全体的な状態を制御' + \
        'し、 ANY TABLE権限を持つユーザーによる操作の対象とすべきではないため、このパラメ' + \
        'ータは常にFALSEに設定する必要があります。'
    refs = {'CIS': 'Recommendation 2.2.5', 'STIG': 'Rule SV-76079r2'}
#    sat.finding('Access to Dictionary Objects', 'CONF.SYSOBJ', summary,
#        severity, details, remarks, refs)
    sat.finding('ディクショナリオブジェクトへのアクセス'.decode('utf-8'), 'CONF.SYSOBJ', summary,
        severity, details, remarks.decode('utf-8'), refs)

    checked, num_issues, details = param_should('SQL92_SECURITY', 'TRUE')
    if num_issues > 0:
        summary = 'UPDATE and DELETE statements can be used to ' + \
            'infer data values.'
        severity = sat.SEV_MEDIUM
    else:
        summary = 'Data inference attacks are properly blocked.'
        severity = sat.SEV_OK
#    remarks = 'When SQL92_SECURITY is set to TRUE, UPDATE and ' + \
#        'DELETE statements that refer to a column in their WHERE ' + \
#        'clauses will succeed only when the user has the ' + \
#        'privilege to SELECT from the same column. This ' + \
#        'parameter should be set to TRUE so that this ' + \
#        'requirement is enforced in order to prevent users from ' + \
#        'inferring the value of a column which they do not have ' + \
#        'the privilege to view.\n'
    remarks = 'SQL92_SECURITYはTRUEに設定されている時、UPDATEやDELETE文をユーザが実行する場合、' + \
        'ユーザがその列にSELECTする権限も持っていなければなりません。データの' + \
        '参照権限を持っていないユーザが列の値を推測する攻撃から防ぐために、このパラメータ' + \
        'をTRUEに設定する必要があります。'
    refs = {'CIS': 'Recommendation 2.2.17', 'STIG': 'Rule SV-75919r1'}
#    sat.finding('Inference of Table Data', 'CONF.INFER', summary,
#        severity, details, remarks, refs)
    sat.finding('表データへの推定'.decode('utf-8'), 'CONF.INFER', summary,
        severity, details, remarks.decode('utf-8'), refs)

    checked, num_issues, details = \
                  param_should_not('REMOTE_LOGIN_PASSWORDFILE', 'SHARED', \
                                    'EXCLUSIVE')
    if num_issues > 0:
        summary = 'The password file is not configured correctly.'
        severity = sat.SEV_LOW
    else:
        severity = sat.SEV_OK
        summary = 'The password file is configured correctly.'
#    remarks ='The REMOTE_LOGIN_PASSWORDFILE set to EXCLUSIVE allows ' + \
#             'the password file to contain distinct entries for each ' + \
#             'administrative user allowing them to be individually audited '+ \
#             'and tracked for their actions. It also allows passwords to be '+ \
#             'updated using the ALTER USER command.'
    remarks ='REMOTE_LOGIN_PASSWORDFILEをEXCLUSIVEに設定すると、' + \
             'パスワードファイルに各管理ユーザーの個別のエントリを含めることができ、' + \
             'それらを個別に監査してその動作を追跡することができます。'+ \
             'また、ALTER USERコマンドを使用してパスワードを更新することもできます。'
    refs = {'STIG': 'Rule SV-75921r2'}
#    sat.finding('Access to Password File', 'CONF.PWDFILE', summary,
#        severity, details, remarks, refs)
    sat.finding('パスワードファイルへのアクセス'.decode('utf-8'), 'CONF.PWDFILE', summary,
        severity, details, remarks.decode('utf-8'), refs)
        
def connection_parameter_checks():
    checked, num_issues, details = param_should('REMOTE_LISTENER', '')
    checked, num_issues, details = \
        param_should_not('SEC_PROTOCOL_ERROR_FURTHER_ACTION', 'CONTINUE',
             '(DELAY,integer) or (DROP,integer)', checked, num_issues, details)
    checked, num_issues, details = \
        param_should_not('SEC_PROTOCOL_ERROR_TRACE_ACTION', 'NONE',
             'TRACE, LOG, or ALERT', checked, num_issues, details)
    checked, num_issues, details = \
        param_should('SEC_RETURN_SERVER_RELEASE_BANNER', 'FALSE',
             checked, num_issues, details)

    if checked == 0:
        sat.diag('Skipped Network Communication Parameter Check')
        return

    summary = param_check_summary(checked, num_issues)

    if num_issues > 0:
        severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_OK

#    remarks = "REMOTE_LISTENER allows a network listener running on " \
#                  "another system to be used. This parameter should " \
#                  "normally be unset to ensure that the local listener " \
#                  "is used. " \
#                  "The SEC_PROTOCOL_ERROR parameters control the " \
#                  "database server's response when it receives " \
#                  "malformed network packets from a client. Because " \
#                  "these malformed packets may indicate an attempted " \
#                  "attack by a malicious client, the parameters should " \
#                  "be set to log the incident and terminate the " \
#                  "connection. SEC_RETURN_SERVER_RELEASE_BANNER should " \
#                  "be set to FALSE to limit the information that is " \
#                  "returned to an unauthenticated client, which could be " \
#                  "used to help determine the server's version number and " \
#                  "thus the vulnerabilities."
    remarks = 'REMOTE_LISTENERパラメータはほかのシステムで動作しているネットワークリスナーを利用することを許可します。' + \
        'このパラメータは通常ローカルリスナーの利用を強制するために値を設定しないようにする必要があります。' + \
        'SEC_PROTOCOL_ERRORパラメータは、クライアントからの不正なネットワークパケットを受' + \
        '信したとき、データベース・サーバの応答を制御します。これらの不正な形式のパケット' + \
        'は、悪意のあるクライアントによって試みられた攻撃を示す可能性があるため、パラメー' + \
        'タは、インシデントをログに記録し、接続を終了するように設定する必要があります。 S' + \
        'EC_RETURN_SERVER_RELEASE_BANNERパラメータは、サーバーのバージョンや脆弱性を判断' + \
        'するために使用することができ、認証されていないクライアントに返される情報を制限す' + \
        'るために、 FALSEに設定する必要があります。'
    refs = {'CIS': 'Recommendation 2.2.7, 2.2.14, 2.2.15, 2.2.16', 
            'STIG': 'Rule SV-76305r4'}

#    sat.finding('Network Communication', 'CONF.NETCOM', summary,
#        severity, details, remarks, refs)
    sat.finding('ネットワーク通信'.decode('utf-8'), 'CONF.NETCOM', summary,
        severity, details, remarks.decode('utf-8'), refs)

def os_parameter_checks():
    checked, num_issues, details = param_should('REMOTE_OS_AUTHENT', 'FALSE')
    checked, num_issues, details = \
       param_should('REMOTE_OS_ROLES', 'FALSE', checked, num_issues, details)
    severe_issues = num_issues
    checked, num_issues, details = \
       param_should('OS_ROLES', 'FALSE', checked, num_issues, details)
 
    if checked == 0:
        sat.diag('Skipped External OS Authorization Parameter Check')
        return

    summary = param_check_summary(checked, num_issues)

    if severe_issues > 0:
        severity = sat.SEV_HIGH
    elif num_issues > 0:
        severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_OK

#    remarks = "The OS_ROLES parameter " + \
#        "determines whether roles granted to users are controlled " + \
#        "by GRANT statements in the database or by the database server's " + \
#        "operating system. " + \
#        "REMOTE_OS_AUTHENT and REMOTE_OS_ROLES allow the client operating " + \
#        "system to set the database user and roles. " + \
#        "All of these parameters " + \
#        "should be set to FALSE so that the authorizations " + \
#        "of database users are managed by the database itself."
    remarks = 'OS_ROLESパラメータはユーザーに付与されたロールが、データベースでの' + \
        'GRANT文またはオペレーティングシステム環境のどちらで制御されているかどうかを' + \
        '判断します。REMOTE_OS_AUTHENTとREMOTE_OS_ROLESパラメータは、' + \
        'クライアントのオペレーティングシステムがデータベースユーザーとロールをセットすることを許可します。' + \
        'データベース・ユーザーの権限を、データベース自身によって管理するた' + \
        'めに、すべてのパラメータをFALSEに設定する必要があります。'
    refs = {'CIS': 'Recommendation 2.2.6, 2.2.9, 2.2.10', 
            'STIG': 'Rule SV-75915r1, SV-75917r1'}

#    sat.finding('External OS Authorization', 'CONF.EXTAUTH', summary,
#        severity, details, remarks, refs)
    sat.finding('OS認可の外部委譲'.decode('utf-8'), 'CONF.EXTAUTH', summary,
        severity, details, remarks.decode('utf-8'), refs)

def utl_dir_parameter_check():
    checked = 0
    num_issues = 0
    details = ''

    val = sys_param_dict.get('UTL_FILE_DIR')

    if val is None:
        if target_db_version < '18':
            sat.diag('Skipped File System Access Parameter Check')
        return
    else:
        checked += 1

    if len(val) == 0:
        details = 'UTL_FILE_DIR=\'\''
    else:
        num_issues += 1
        details = 'UTL_FILE_DIR=' + val + '. ' + \
                  'Recommended value is \'\'.'

    summary = param_check_summary(checked, num_issues)

    if num_issues > 0:
        if target_db_version >= '12.2':
           severity = sat.SEV_HIGH
        else:
           severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_OK

#    remarks12 = "The UTL_FILE_DIR parameter controls which part "  \
#                  "of the database server's file system can be accessed by " \
#                  "PL/SQL code. Because the directories specified in " \
#                  "the UTL_FILE_DIR parameter may be accessed by " \
#                  "any database user, it should be set to specify one or " \
#                  "more safe directories that do not contain "       \
#                  "restricted files such as the configuration or "   \
#                  "data files for the database. For maximum security, " \
#                  "use directory objects which " \
#                  "allow finer grained control of access, rather than " \
#                  "relying on this parameter."
    remarks12 = 'UTL_FILE_DIRパラメータは、PL/SQLによってアクセスできるデータベース・サーバのファイルシステムの' + \
        '場所を制御します。UTL_FILE_DIRパラメータで指定されたディレクトリは、すべてのデー' + \
        'タベース・ユーザーがアクセスすることができるので、データベースの設定やデータファ' + \
        'イルなどの制限されたファイルを含まない安全なディレクトリを指定するように設定しな' + \
        'ければなりません。' + \
        'セキュリティを最大限に高めるために、このパラメータを利用せずに' + \
        'より詳細にアクセス制御できるディレクトリオブジェクトを使用してください。'

#    remarks12c = "The initialization parameter UTL_FILE_DIR is deprecated, " \
#                 "and it is recommended that you do not provide UTL_FILE_DIR " \
#                 "access. Instead, it is recommended to use directory " \
#                 "object feature."
    remarks12c = '初期化パラメータUTL_FILE_DIRは推奨されていません。' + \
        'UTL_FILE_DIRアクセスを提供しないことをお薦めします。 代わりに、' + \
        'ディレクトリ・オブジェクト機能を使用することをお勧めします。'

    if target_db_version >= '12.2':
       remarks = remarks12 + "\n" + remarks12c
    else:
       remarks = remarks12

    refs = {'CIS': 'Recommendation 2.2.11'}

#    sat.finding('File System Access', 'CONF.FILESYS', summary,
#        severity, details, remarks, refs)
    sat.finding('ファイルシステムへのアクセス'.decode('utf-8'), 'CONF.FILESYS', summary,
        severity, details, remarks.decode('utf-8'), refs)

def trace_files():
    checked, num_issues, details = param_should('_TRACE_FILES_PUBLIC', 'FALSE')

    summary = param_check_summary(checked, num_issues)

    if num_issues > 0:
        severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_OK

#    remarks = "The hidden parameter _TRACE_FILES_PUBLIC " + \
#        "determines whether trace files generated by the database " + \
#        "should be accessible to all OS users. " + \
#        "Since these files may contain sensitive information, " + \
#        "access should be limited by setting this parameter to FALSE."
    remarks = '_TRACE_FILES_PUBLIC隠しパラメータはデータベースによって生成されるトレースファイルを' + \
        'すべてのOSユーザーからアクセスできるようにするかどうかを決定します。' + \
        'これらのファイルには重要な情報が含まれている可能性があるため' + \
        'アクセスを制限するためにこのパラメータをFALSEに設定する必要があります。'
    refs = {'CIS': 'Recommendation 2.2.18',
            'STIG': 'Rule: SV-75955r1'}

#    sat.finding('Trace Files', 'CONF.TRACE', summary,
#        severity, details, remarks, refs)
    sat.finding('トレースファイル'.decode('utf-8'), 'CONF.TRACE', summary,
        severity, details, remarks.decode('utf-8'), refs)

def instance_name_check():
    instance_data = sat.get_data('instance_name', 1)
    major_num = target_db_version.split('.',1)[0] #Major
    instn_idx = sat.get_index('instance_name', 'inst_name')
    if instn_idx is None:
       sat.diag('Skipped Instance Name check.')
    else:
       inst_name = instance_data[0][instn_idx]
       if major_num in inst_name:
          summary = 'Instance name may contain database version number.'
          severity = sat.SEV_LOW
       else:
          summary = 'Instance name does not contain database version number.'
          severity = sat.SEV_OK
       details = 'Instance Name = ' + inst_name + '\n' + \
                 'Database Version = ' + target_db_version
#       remarks = 'Instance names should not contain Oracle version ' + \
#                 'numbers. Service names may be discovered by unauthenticated '+ \
#                 'users. If the service name includes version numbers or ' + \
#                 'other database product information, a malicious user may ' + \
#                 'use that information to develop a targeted attack.'
       remarks = 'インスタンス名にOracleのバージョン番号を含むことはいけません。' + \
                 '認証されていないユーザーによってサービス名が発見される可能性があります。'+ \
				 'サービス名にバージョン番号または他のデータベース製品情報が含まれている場合、'+ \
                 '悪意のあるユーザーはその情報を使用して標的型攻撃を行う可能性があります。'
       refs = { 'STIG': 'Rule SV-75903r1' }
#       sat.finding('Instance Name Check', 'CONF.INSTNM', summary,
#           severity, details, remarks, refs)
       sat.finding('インスタンス名チェック'.decode('utf-8'), 'CONF.INSTNM', summary,
           severity, details, remarks.decode('utf-8'), refs)

def triggers():
    data = sat.get_data('triggers', 1)
    if data is None:
        sat.diag('Skipped Triggers')
        return
    owner = sat.get_index('triggers', 'owner')
    name = sat.get_index('triggers', 'trigger_name')
    status = sat.get_index('triggers', 'status')
    event = sat.get_index('triggers', 'triggering_event')

    trgs = [x[owner]+'.'+x[name]+'(' + x[status] + ')'
            for x in data if x[event].rstrip() == 'LOGON']
    if len(trgs) > 0:
        summary = 'Found ' + sing_plural(len(trgs), 'logon trigger.', 
                                                    'logon triggers.')
        details = 'Logon triggers: ' + join_list(trgs) + '\n'
    else:
        summary = 'No logon triggers found. '
        details = ''

    default_triggers = ['LBACSYS.LBAC$AFTER_CREATE', 'LBACSYS.LBAC$AFTER_DROP',
         'LBACSYS.LBAC$BEFORE_ALTER', 'MDSYS.SDO_GEOR_ADDL_TRIGGER',
         'MDSYS.SDO_GEOR_BDDL_TRIGGER', 'MDSYS.SDO_TOPO_DROP_FTBL',
         'MDSYS.SDO_DROP_USER', 'MDSYS.SDO_NETWORK_DROP_USER',
         'MDSYS.SDO_ST_SYN_CREATE',
         'SYS.NO_VM_DROP', 'SYS.NO_VM_DROP_A', 
         'SYS.NO_VM_CREATE', 'SYS.NO_VM_ALTER', 
         'SYS.AURORA$SERVER$STARTUP', 'SYS.AURORA$SERVER$SHUTDOWN',
         'SYS.CDC_ALTER_CTABLE_BEFORE', 'SYS.CDC_CREATE_CTABLE_AFTER',
         'SYS.CDC_CREATE_CTABLE_BEFORE', 'SYS.CDC_DROP_CTABLE_BEFORE',
         'SYS.LOGMNRGGC_TRIGGER', 'SYS.SYSLSBY_EDS_DDL_TRIG', 
         'EXFSYS.EXPFIL_RESTRICT_TYPEEVOLVE', 'EXFSYS.EXPFIL_ALTEREXPTAB_MAINT',
         'EXFSYS.EXPFIL_DROPOBJ_MAINT', 'EXFSYS.EXPFIL_DROPUSR_MAINT',
         'EXFSYS.RLMGR_TRUNCATE_MAINT',
         'WMSYS.NO_VM_DDL', 'WMSYS.NO_VM_DROP_A']

    trgs = [x[owner]+ '.' + x[name] for x in data if x[status] == 'DISABLED']
    trgs = [x for x in trgs if x not in default_triggers]

    if len(trgs) > 0:
        summary += ' Found ' + sing_plural(len(trgs), 'disabled trigger.', 
                                                      'disabled triggers.')
        severity = sat.SEV_LOW
        details += 'Disabled triggers: ' + join_list(trgs)
    else:
        summary += ' No disabled triggers found.'
        severity = sat.SEV_OK

    if details == '':
        details = None

#    remarks = 'A trigger is code that executes whenever a specific ' + \
#        'event occurs, such as inserting data in a table or ' + \
#        'connecting to the database. Disabled Oracle provided triggers could be a ' + \
#        'potential cause for concern because whatever protection ' + \
#        'or monitoring they may be expected to provide is ' + \
#        'disabled.'
    remarks = 'トリガーは、テーブルにデータを挿入したり、データベースに接続したり特定のイベント' + \
        'が起こった際に実行されるコードです。無効化されたOracle提供のトリガーは、データベースの監視や保護' + \
        'する目的で定義されているものが無効になっているかもしれないので、潜在的なリスクの可能性があります。'

#    sat.finding('Triggers', 'CONF.TRIG', summary, severity=severity,
#                details=details, remarks=remarks)
    sat.finding('トリガー'.decode('utf-8'), 'CONF.TRIG', summary, severity=severity,
                details=details, remarks=remarks.decode('utf-8'))

def disabled_constraint():
    data = sat.get_data('disabled_constraint', 1)
    if data is None:
        sat.diag('Skipped Disabled Constraints')
        return
    owner = sat.get_index('disabled_constraint', 'owner')
    tab_name = sat.get_index('disabled_constraint', 'table_name')
    constraint_name = sat.get_index('disabled_constraint',
                                        'constraint_name')

    constraint_list = [x[constraint_name] + ' on ' + x[owner] + \
                       '.' + x[tab_name] for x in data]

    if len(data) > 0:
        severity = sat.SEV_LOW
        summary = 'Found ' + \
                  sing_plural(len(data), 'disabled constraint.',
                                         'disabled constraints.')
        details = 'Disabled constraints: ' + \
                  join_list(constraint_list);
    else:
        severity = sat.SEV_OK
        summary = 'No disabled constraints found.'
        details = None

#    remarks = 'Constraints are used to enforce and guarantee specific ' + \
#        'relationships between data items stored in the ' + \
#        'database. Disabled constraints are a potential cause ' + \
#        'for concern because the conditions they ensure are not ' + \
#        'enforced.'
    remarks = '制約は、データベースに格納されたデータ間の関係性を保証し、強制するために使用さ' + \
        'れます。無効化された制約は、強制されたデータの関係性が確実になっていない潜在的な' + \
        'リスクの可能性があります。'

#    sat.finding('Disabled Constraints', 'CONF.CONST', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('無効化された制約'.decode('utf-8'), 'CONF.CONST', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))

def external_procedure():
    data = sat.get_data('external_procedure', 1)
    dict = parse_configfile('listener.ora')
    if data is None or dict is None:
        sat.diag('Skipped External Procedures')
        return
    extproc_envs = {}
    owner = sat.get_index('external_procedure', 'owner')
    lib_name = sat.get_index('external_procedure', 'library_name')

    lib_list = [x[owner] + '.' + x[lib_name] for x in data]

    for k, v in dict.items():
        if k.startswith('SID_LIST_'):
            sid_list = v.get('SID_LIST', {})
            sid_desc_list = sid_list.get('SID_DESC', [])
            if type(sid_desc_list) != type([]):
                sid_desc_list = [sid_desc_list]
            for x in sid_desc_list:
                if x.get('PROGRAM') == 'extproc':
                    name = x.get('SID_NAME', '(no name)')
                    env_val = x.get('ENVS', {})
                    if type(env_val) == type(''):
                        envlex = tokenizer(env_val)
                        try:
                            env_val = parse_value(envlex)
                            if type(env_val) != type({}):
                                sat.diag('Failed to get the ENVS value')
                                env_val = {}
                        except Exception as e:
                            sat.diag('Failed to parse ENVS: ' + str(e))
                            env_val = {}
                    extproc_envs[name] = env_val

    details = ''
    if len(data) > 0:
        severity = sat.SEV_UNKNOWN
        summary = 'Found ' + sing_plural(len(data), 'external procedure.',
                                                    'external procedures.')
        details = 'External procedures: %s \n\n' % join_list(lib_list);
    else:
        severity = sat.SEV_OK
        summary = 'No external procedures found.'

    if len(extproc_envs) > 0:
        severity = sat.SEV_UNKNOWN
        summary += ' Found %s.' % \
                   sing_plural(len(extproc_envs), 
                               'external service', 'external services')
        details += 'Listener services for external procedures: \n'
        for name, env in extproc_envs.items():
            ddls = env.get('EXTPROC_DLLS', '(not set)')
            details += name + ': EXTPROC_DLLS=' + ddls + '\n'
            if ddls == 'ANY' or ddls == '(not set)':
                severity = sat.SEV_LOW
    else:
        summary += ' No external services found.'

#    remarks = 'External procedures allow code written in other languages ' + \
#              'to be executed from PL/SQL. Note that modifications to ' + \
#              'external code cannot be controlled by the database. Be ' + \
#              'careful to ensure that only trusted code libraries are ' + \
#              'available to be executed. ' + \
#              'Although the database can spawn its own process to execute ' + \
#              'the external procedure, it is advisable to configure a ' + \
#              'listener service for this purpose so that the external ' + \
#              'code can run as a less-privileged OS user. The ' + \
#              'listener configuration should set EXTPROC_DLLS to identify ' + \
#              'the specific shared library code that can be executed ' + \
#              'rather than using the default value ANY.'
    remarks = '外部プロシージャにより、他の言語で書かれたコードを、PL/SQLから実行でき' + \
        'ます。外部コードの変更はデータベースによって制御することができないことに注意してください。' + \
        'また、信頼できるコードライブラリのみ実行可能であるようにに注意してください。' + \
        'データベースは、外部プロシージャを実行するための独自のプロセスを生成することがで' + \
        'きますが、より小さい権限のOSユーザーとして外部コードを実行できるように、この目的の' + \
        'ためにリスナーサービスを設定することをお勧めします。' + \
        'リスナー構成時には、EXTPROC_DLLSをデフォルト値ANYを使用するのではなく、' + \
        '特定の共有ライブラリコードだけを実行することができるよう明示的に指定する必要があります。'
    refs = {'CIS': 'Recommendation 2.1.2', 'STIG': 'Rule SV-76091r2, SV-76173r1, SV-76175r2' }

#    sat.finding('External Procedures', 'CONF.EXTPROC', summary,
#        severity, details, remarks, refs)
    sat.finding('外部プロシージャ'.decode('utf-8'), 'CONF.EXTPROC', summary,
        severity, details, remarks.decode('utf-8'), refs)

def directories_info():
    data = sat.get_data('directory_info', 1)
    db_info_data = sat.get_data('db_identity', 1)

    if data is None or db_info_data is None:
        sat.diag('Skipped Directory Objects')
        return

    platform = sat.get_index('db_identity', 'platform')
    if 'WINDOWS' in db_info_data[0][platform].upper():
        path_delimiter = '\\'
    else:
        path_delimiter = '/'

    priv_data = sat.get_data('directory_priv', 11)
    if priv_data is None:
         priv_data = sat.get_data('directory_priv', 1)

    if priv_data is None:
        sat.diag('Skipped Directory Privileges')
        priv_data = []
    else:
        dir_name = sat.get_index('directory_priv', 'directory_name')
        grantee = sat.get_index('directory_priv', 'grantee')
        priv = sat.get_index('directory_priv', 'privilege')

    db_file_data = sat.get_data('data_files', 1)
    if db_file_data is None:
        sat.diag('Skipped Data Files')
        db_file_data = []
    else:
        file_name = sat.get_index('data_files', 'file_name')

    name = sat.get_index('directory_info', 'directory_name')
    path = sat.get_index('directory_info', 'directory_path')

    oh_dir = get_from_env_data('ORACLE_HOME')
    if oh_dir is None:
        sat.diag('Skipped ORACLE_HOME Directory Check')
    else:
        dbs_dir = oh_dir + path_delimiter + 'dbs'
        bin_dir = oh_dir + path_delimiter + 'bin'

    audit_file_dir = sys_param_dict.get('AUDIT_FILE_DEST')

    dict = {}
    dict['oh_dir'] = []
    dict['dbs_dir'] = []
    dict['bin_dir'] = []
    dict['audit_file_dir'] = []
    dict['data_file_dir'] = []
    write_exec_dirs = []

    if len(data) > 0:
        summary = 'Found ' + sing_plural(len(data), 'directory object.',
                                                    'directory objects.')
    else:
        summary = 'No directory objects found.'

    db_file_dict = {}
    for x in db_file_data:
        db_file_dir = x[file_name][0:x[file_name].rfind(path_delimiter)+1]
        db_file_name = x[file_name].split(path_delimiter)[-1]
        if not db_file_dict.get(db_file_dir): 
            db_file_dict[db_file_dir] = []
        db_file_dict[db_file_dir].append(db_file_name) 

    details =''
    for x in data:
        if x[path] and x[path][-1] != path_delimiter:
            dir_path = x[path] + path_delimiter
        else:
            dir_path = x[path]
        details += 'Directory Name: ' + x[name] + '\n'
        details += 'Path = ' +  dir_path

        grantees = []
        write_access = False
        execute_access = False

        grantees_create_any_dir, unique_users, num = get_sys_priv_grantees('CREATE ANY DIRECTORY')

        for y in priv_data:
          if y[grantee] not in grantees_create_any_dir:
            if x[name] == y[dir_name]:
                g_info = y[grantee] + '(' +  y[priv] + ')'
                grantees.append(g_info)
                if y[priv] == 'WRITE':
                    write_access = True
                elif y[priv] == 'EXECUTE':
                    execute_access = True

        if len(grantees) > 0:
            details += '\nUsers or roles with access: '
            details += join_list(grantees)

        if db_file_dict.get(dir_path):
            details += '\nAccess to data files: '
            details += join_list(db_file_dict[dir_path])
            dict['data_file_dir'].append(x[name])
        
        details += '\n\n'

        if write_access and execute_access:
            write_exec_dirs.append(x[name])

        if oh_dir is not None:
            if x[path] == oh_dir:
                dict['oh_dir'].append(x[name])
            elif x[path] == dbs_dir:
                dict['dbs_dir'].append(x[name])
            elif x[path] == bin_dir:
                dict['bin_dir'].append(x[name])

        if audit_file_dir is None:
            sat.diag('Skipped Audit File Destination Check')
        else:
            if x[path] == audit_file_dir:
                dict['audit_file_dir'].append(x[name])

    count = len(dict['oh_dir']) + len(dict['dbs_dir']) + \
            len(dict['bin_dir']) + len(dict['audit_file_dir']) + \
            len(dict['data_file_dir']) 

    if write_exec_dirs or dict['dbs_dir'] or \
       dict['bin_dir'] or dict['audit_file_dir'] or dict['data_file_dir']:
        severity = sat.SEV_MEDIUM
    elif dict['oh_dir']:
        severity = sat.SEV_MEDIUM
    else:
        severity = sat.SEV_UNKNOWN

    if count > 0:
        summary += ' Found ' + sing_plural(count, 'directory object', 
                                                  'directory objects') + \
                   ' allowing access to restricted Oracle directory paths.'

        details += '\n'
        if len(dict['oh_dir']) > 0:
            details += 'Access to $ORACLE_HOME: ' + \
                       join_list(dict['oh_dir']) + '\n'
        if len(dict['dbs_dir']) > 0:
            details += 'Access to $ORACLE_HOME/dbs: ' + \
                       join_list(dict['dbs_dir']) + '\n'
        if len(dict['bin_dir']) > 0:
            details += 'Access to $ORACLE_HOME/bin: ' + \
                       join_list(dict['bin_dir']) + '\n'
        if len(dict['audit_file_dir']) > 0:
            details += 'Access to audit file destination: ' + \
                       join_list(dict['audit_file_dir']) + '\n'
        if len(dict['data_file_dir']) > 0:
            details += 'Access to data file directories: ' + \
                       join_list(dict['data_file_dir']) + '\n'
    else:
        summary += ' No directory objects allow access to ' + \
                           'restricted Oracle directory paths.'

    if len(write_exec_dirs) > 0:
        summary += ' Found ' + sing_plural(len(write_exec_dirs), 
                                           'directory object',
                                           'directory objects') + \
                   ' with both write and execute access.'

        details += '\nDirectories with both write and execute access: '
        details += join_list(write_exec_dirs)
    else:
        summary += ' No directory objects allow both write and execute access.'

#    remarks = "Directory objects allow access to the server's file " \
#        "system from PL/SQL code within the database. Access to " \
#        "files that are used by the database kernel itself " \
#        "should not be permitted, as this may alter the " \
#        "operation of the database and bypass its access " \
#        "controls."
    remarks = 'ディレクトリ・オブジェクトは、データベース内のPL/SQLコードからサーバーのファイル' + \
        'システムへのアクセスを許可します。データベースの動作を変更し、アクセス制' + \
        '御をバイパスするリスクがあるため、データベースカーネル自身が使用するファイルへの' + \
        'アクセスは許可すべきではありません。'
#    sat.finding('Directory Objects', 'CONF.DIR', summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('ディレクトリ・オブジェクト'.decode('utf-8'), 'CONF.DIR', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))

def dblink_info():
    data = sat.get_data('db_links', 1)
    if data is None:
        sat.diag('Skipped Database Links')
        return

    link_name = sat.get_index('db_links', 'db_link')
    username = sat.get_index('db_links', 'username')
    owner = sat.get_index('db_links', 'owner')

    val = sys_param_dict.get('GLOBAL_NAMES')
    if val is None:
        details = ''
        sat.diag('Skipped GLOBAL_NAMES parameter check')
    else:
        details = 'GLOBAL_NAMES=' + display_string(val) + '\n\n'

    gn_summary = ''
    severity = sat.SEV_OK
    gn_checked, gn_num_issues, gn_details = \
       param_should_not('GLOBAL_NAMES', 'FALSE', 'TRUE')
    if gn_num_issues > 0:
        severity = sat.SEV_LOW
        gn_summary = ' Database link names may not be same as remote database '+\
                     'connection they define.'

    for priv in ('CREATE DATABASE LINK', 'CREATE PUBLIC DATABASE LINK'):
        g_list, unique_users, num_admin = get_sys_priv_grantees(priv)
        details += 'Users with ' + priv + ' privilege: ' + \
            join_list(g_list) + '\n'

    details += '\n'
    private_links = []
    public_links = []
    if len(data) == 0:
        summary = 'No database links found.'
        severity = max(severity, sat.SEV_OK)
    else:
        summary = 'Found ' + sing_plural(len(data),
            'database link', 'database links') + '.'
        severity = max(severity, sat.SEV_UNKNOWN)
        for x in data:
            if x[username]:
                link = '%s (User %s)' % (x[link_name], x[username])
            else:
                link = x[link_name]
            if x[owner] == 'PUBLIC':
                public_links.append(link)
            else:
                private_links.append('%s: %s' % (x[owner], link))

        if private_links:
            details += 'Private links:\n'
            for link in private_links:
                details += link + '\n'
            details += '\n'
        if public_links:
            details += 'Public links:\n'
            for link in public_links:
                details += link + '\n'
    summary += gn_summary    

#    remarks = 'Database links allow users to execute SQL statements ' + \
#        'that access tables in other databases. This allows for both ' + \
#        'querying and storing data on the remote database. ' + \
#        'It is advisable to set GLOBAL_NAMES to TRUE in order to ensure ' + \
#        'that link names match the databases they access.'
    remarks = 'データベース・リンクは、ユーザーが他のデータベース内のテーブルにアクセスするSQL' + \
        '文を実行することを可能にします。これは、リモート・データベースのデータの参照と格' + \
        '納の両方を可能にします。データベースリンク名とアクセスするデータベース名を一致させるために' + \
        'GLOBAL_NAMESパラメータをTRUEに設定することをお勧めします'
    refs = {'CIS': 'Recommendation 2.2.3', 
            'STIG': 'Rule SV-75941r1, SV-75997r1, SV_76019r1'}
#    sat.finding('Database Links', 'CONF.LINKS', summary,
#        severity, details, remarks, refs)
    sat.finding('データベースリンク'.decode('utf-8'), 'CONF.LINKS', summary,
        severity, details, remarks.decode('utf-8'), refs)

def network_acl():
    data = sat.get_data('network_acl', 1)
    if data is None:
        sat.diag('Skipped Network ACL')
        return

    acl = sat.get_index('network_acl', 'acl')
    host = sat.get_index('network_acl', 'host')
    l_port = sat.get_index('network_acl', 'lower_port')
    u_port = sat.get_index('network_acl', 'upper_port')

    if len(data) > 0:
        summary = 'Found ' + \
                  sing_plural(len(data), 'network ACL.', 'network ACLs.')
    else:
        summary = 'No network ACLs found.'

    data2 = sat.get_data('network_acl_privilege', 1)
    if data2 is None:
        sat.diag('Skipped Network ACL privilege')
    else:
        acl2 = sat.get_index('network_acl_privilege', 'acl')
        prin = sat.get_index('network_acl_privilege', 'principal')
        priv = sat.get_index('network_acl_privilege', 'privilege')
        grant = sat.get_index('network_acl_privilege', 'is_grant')
        inv = sat.get_index('network_acl_privilege', 'invert')
        sdate = sat.get_index('network_acl_privilege', 'start_date')
        edate = sat.get_index('network_acl_privilege', 'end_date')

    if len(data) == 0:
        details = None
    else:
        details = ''
        for x in data:
            if x[l_port] is None:
                lower = 'Min'
            else:
                lower = x[l_port]
            if x[u_port] is None:
                upper = 'Max'
            else:
                upper = x[l_port]

            details += x[acl] + ' (Host: ' + x[host] + ', '
            details += 'Ports: %s - %s)\n' % (lower, upper)

            if data2 is None:
                continue

            plist = []
            for y in data2:
                if y[inv].upper() == 'TRUE':
                    details += 'Inverse Principal: %s, ' % y[prin]
                else:
                    details += 'Principal: %s, ' % y[prin]
                if y[grant]:
                    details += 'Action: grant, '
                else:
                    details += 'Action: deny, '
                details += 'Privilege: %s' % y[priv]
                if len(y[sdate]) > 0:
                    details += ', start_date=' + y[sdate]
                if len(y[edate]) > 0:
                    details += ', end_date=' + y[edate]
                details += '\n'
            details += '\n'

    severity = sat.SEV_UNKNOWN
#    remarks = 'Network ACLs control the external servers that database ' + \
#        'users can access using network packages such as UTL_TCP ' + \
#        'and UTL_HTTP. Specifically, a database user needs the connect ' + \
#        'privilege to an external network host computer if he or she is ' + \
#        'connecting using the UTL_TCP, UTL_HTTP, UTL_SMTP, and UTL_MAIL ' + \
#        'utility packages. To convert between a host name and its IP ' + \
#        'address using the UTL_INADDR package, the resolve privilege is ' + \
#        'required. Make sure that these permissions are limited ' + \
#        'to the minimum required by each user.'
    remarks = 'ネットワークACLは、データベース・ユーザーがUTL_TCPやUTL_HTTPなどのネットワーク・' + \
        'パッケージを使用してアクセスできる外部サーバを制御します。' + \
        '具体的には、もし誰かがUTL_TCP、UTL_HTTP、UTL_SMTPおよびUTL_MAILのユーティリティ' + \
        '・パッケージを使用して接続する時、データベース・ユーザーは外部ネットワークのホス' + \
        'トコンピュータに接続する権限が必要です。' + \
        'UTL_INADDRパッケージを使用して、ホスト名とIPアドレスを変換するには、re' + \
        'solve権限が必要です。これらの権限が、各ユーザーに必要最小限に制限されていること' + \
        'を確認します。'

#    sat.finding('Network Access Control', 'CONF.NETACL', summary,
#                severity, details=details, remarks=remarks)
    sat.finding('ネットワークアクセス制御'.decode('utf-8'), 'CONF.NETACL', summary,
                severity, details=details, remarks=remarks.decode('utf-8'))

def xml_acl():
    data = sat.get_data('xml_acl', 1)
    if data is None:
        sat.diag('Skipped XML ACL')
        return
    xml_acl = sat.get_index('xml_acl', 'xml_acl')

    if len(data) > 0:
        summary = 'Found ' + sing_plural(len(data), 'XML Database ACL.',
                                                    'XML Database ACLs.')
        details = ''
        for x in data:
            acl = x[xml_acl]
            details += process_xml_acl(acl) + '\n'
    else:
        summary = 'No XML Database ACLs found. '
        details = None

    severity = sat.SEV_UNKNOWN
#    remarks = 'XML ACLs control access to database resources using the ' + \
#        'XML DB feature. Every resource in the Oracle XML DB Repository ' + \
#        'hierarchy has an associated ACL. The ACL mechanism specifies ' + \
#        'a privilege-based access control for resources to principals, ' + \
#        'which are database users or roles. Whenever a resource is ' + \
#        'accessed, a security check is performed, and the ACL determines ' + \
#        'if the requesting user has sufficient privileges to access the ' + \
#        'resource. Make sure that these privileges are limited to the ' + \
#        'minimum required by each user.'
    remarks = 'XML ACLは、 XML DBの機能を使用した、データベース・リソースへのアクセスを制御し' + \
        'ます。 Oracle XML DBリポジトリ階層内のすべてのリソースは、関連するACLを持ってい' + \
        'ます。ACLメカニズムは、データベース・ユーザーまたはロールのプリンシパルへのリソ' + \
        'ースに対する権限ベースのアクセス制御を指定します。リソースがアクセスされるたびに' + \
        '、セキュリティチェックが行われ、ACLは要求しているユーザがリソースにアクセスするための' + \
        '十分な権限を持っているか判断します。これらの権限は、各ユーザーの必要' + \
        '最小限に制限されていることを確認します。'

#    sat.finding('XML Database Access Control', 'CONF.XMLACL', summary,
#           severity, details=details, remarks=remarks)
    sat.finding('XML Databaseアクセス制御'.decode('utf-8'), 'CONF.XMLACL', summary,
           severity, details=details, remarks=remarks.decode('utf-8'))

def rman_bkup():
  cs_data = sat.get_data('cloud_service',1)
  cs_idx = sat.get_index('cloud_service','cs')
  is_cs = 0
  if cs_data is not None:
     is_cs = cs_data[0][cs_idx];
  if con_type == 'PDB' and is_cs != 0:
     return
  else:
     data = sat.get_data('rman_backup_status',1)
     bkupencdata = sat.get_data('bkup_piece_enc',1)

     if data is None:
         sat.diag('Skipped RMAN BACKUP')
         return

     if len(data) <= 0:
        summary = 'No Backup Records found for the last 90 days. '
        severity = sat.SEV_HIGH
        details = None
     else:
        summary = 'Found RMAN Backup Utility Usage. \n'

        details = ''
        severity = sat.SEV_UNKNOWN

        bkup_time = sat.get_index('rman_backup_status', 'ctime')
        bkup_type = sat.get_index('rman_backup_status', 'object_type')
        bkup_media_used = sat.get_index('rman_backup_status', 'output_device_type')
        bkup_is_encrypted = sat.get_index('bkup_piece_enc','encrypted')
        bkup_total = sat.get_index('bkup_piece_enc','num')

        unenc_cnt = 0
        total = 0 
       

        if bkupencdata is not None:
            for y in bkupencdata:
                if y[bkup_is_encrypted] == 'NO':
                   unenc_cnt = int(y[bkup_total])
                total += int(y[bkup_total])
        
        full_date = None
        inc_date = None
        log_date = None
        found_unencrypted = False
        detected_osb = False
        tape_bkup = 0

        for x in data:
            if x[bkup_type] == 'DB FULL': # FULL BACKUP
               full_date = read_date(x[bkup_time])
            elif x[bkup_type] == 'DB INCR': # INCREMENTAL BACKUP
               inc_date = read_date(x[bkup_time])
            elif x[bkup_type] == 'ARCHIVELOG': # LOG BACKUP
               log_date = read_date(x[bkup_time])
               
            if x[bkup_media_used] == 'SBT_TAPE':
               detected_osb = True
               tape_bkup += 1

        if unenc_cnt > 0:
            found_unencrypted = True
            severity = max(severity, sat.SEV_MEDIUM)
        else:
            found_unencrypted = False

        if full_date is not None:
           details += 'Last Full Backup was taken on ' + format_date(full_date) + '. \n';
        if inc_date is not None:
           details += 'Last Incremental Backup was taken on ' + format_date(inc_date) + '. \n';
        if log_date is not None:
           details += 'Last Log Backup was taken on ' + format_date(log_date) + '. \n';
        if detected_osb is False:
           details += 'No Backups were created on Tape using Oracle Secure ' + \
                      'Backup in the last 90 days. \n'
        else:
           details += 'Backup include ' + \
                       sing_plural(tape_bkup, 'backup', 'backups') + \
                      ' created on Tape using Oracle Secure Backup. \n'
        if found_unencrypted:
           details += 'Found ' + str(unenc_cnt) + \
                      ' Unencrypted Backup Pieces out of total ' + \
                      str(total) + ' Backup Pieces made in last 90 days. \n'
        else:
           if total > 0:
              details += 'RMAN configured to encrypt the backup pieces. \n'
           else:
              details += 'No Backup Pieces were found for the last 90 days. \n'

#     remarks = 'Database should be backed up regularly to prevent loss of ' + \
#               'data in the event of a system failure. Oracle Recovery Manager '+ \
#               '(RMAN) allows performing backup and recovery tasks on your '+ \
#               'databases. Unencrypted backup data should not be ' + \
#               'transported on tape or disk to offsite storage for  ' + \
#               'safekeeping. Oracle Secure Backup(OSB) may also be used for ' + \
#               'tape data protection in distributed environment. ' 
     remarks = 'システム障害時にデータが失われるのを防ぐために、データベースは定期的にバックアップする必要があります。' + \
               'Oracle Recovery Manager（RMAN）を使用すると、データベースでバックアップとリカバリのタスクを実行できます。'+ \
               '暗号化されていないバックアップデータは、保管のためにテープまたはディスクでオフサイトストレージに転送しないでください。'+ \
               '分散環境でのテープデータ保護にOracle Secure Backup（OSB）を使用することもできます。'

     refs = { 'STIG': 'Rule SV-76179r1, SV-76183r1, SV-76185r1, SV-76187r1, ' + 
                            'SV-76189r1, SV-76191r1' }

#     sat.finding('Database Backup', 'CONF.BKUP', summary,
#         severity, details=details, remarks=remarks, refs=refs)
     sat.finding('データベースのバックアップ'.decode('utf-8'), 'CONF.BKUP', summary,
         severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)



def param_should(param, rec_val, cnt=0, num_issues=0, msg=''):
    val = sys_param_dict.get(param)

    if val is None:
        return cnt, num_issues, msg
    else:
        val = val.upper()
        cnt += 1

    if val != rec_val:
        num_issues += 1
        msg += param + '=' + display_string(val) + '. ' + \
               'Recommended value is ' + display_string(rec_val)  + '.\n'
    else:
        msg += param + '=' + display_string(val) + '\n'

    return cnt, num_issues, msg

def param_should_not(param, risky_val, rec_val, cnt=0, num_issues=0, msg=''):
    val = sys_param_dict.get(param)

    if val is None:
        return cnt, num_issues, msg
    else:
        val = val.upper()
        cnt += 1

    if val == risky_val:
        num_issues += 1
        msg += param + '=' + display_string(val) + '. ' + \
               'Recommended value is ' + display_string(rec_val)  + '.\n'
    else:
        msg += param + '=' + display_string(val) + '\n'

    return cnt, num_issues, msg

def param_check_summary(num_checked, num_issues):
    summary = 'Examined ' + \
              sing_plural(num_checked, 'initialization parameter. ', 
                                       'initialization parameters. ')

    if num_issues > 0:
        summary += 'Found ' + sing_plural(num_issues, 'issue.', 'issues.')
    else:
        summary += 'No issues found.'

    return summary

def process_xml_acl(xacl):
    try:
        acl = ET.fromstring(xacl)
    except Exception as e:
        sat.diag('Error during XML ACL parsing')
        sat.diag(str(e))
        return ''

    if acl.tag.endswith('acl'):
        ns = acl.tag[:-3]
    else:
        sat.diag('Skipped Invalid XML ACL')
        return ''

    detail = 'Namespace: ' + ns + '\n'

    desc = acl.get('description')
    if desc is not None:
        detail += 'Description: ' + desc + '\n'

    for ace in acl:
        principal = ace.find(ns + 'principal')

        if principal is None:
            invert = ace.find(ns + 'invert')

            if invert is not None:
                ip = invert.find(ns + 'principal')
                detail += 'Inverse Principal: ' + ip.text
            else:
                detail += 'No Principal'
        else:
            detail += 'Principal: ' + principal.text

        type = ace.find(ns + 'grant')
        if type is not None:
            if type.text == 'true':
                detail += ', Action: grant'
            else:
                detail += ', Action: deny'

        priv = ace.find(ns + 'privilege')
        if priv is not None:
            plist = []
            for p in priv:
                plist.append(p.tag.replace(ns, '', 1))
            detail += ', Privileges: ' + join_list(plist) + '\n'

    return detail


def sqlnet_ora():
    dict = parse_configfile('sqlnet.ora')
    if dict is None:
        sat.diag('Skipped SQLNET Parameters')
        return

    sqlnet_network_encryption(dict)
    sqlnet_tcp_nodes(dict)
    sqlnet_banner(dict)

def sqlnet_network_encryption(dict):
    details = ''
    summary = ''
    severity = sat.SEV_OK

    server_enc = dict.get('SQLNET.ENCRYPTION_SERVER')
    if server_enc is None:
        details += 'SQLNET.ENCRYPTION_SERVER is not set ' + \
                   '(default value = ACCEPTED).\n'
        server_enc = 'ACCEPTED'
    else:
        server_enc = server_enc.upper()
        details += 'SQLNET.ENCRYPTION_SERVER = ' + server_enc + '\n'

    server_cs = dict.get('SQLNET.CRYPTO_CHECKSUM_SERVER')
    if server_cs is None:
        details += 'SQLNET.CRYPTO_CHECKSUM_SERVER is not set ' + \
                   '(default value = ACCEPTED).'
        server_cs = 'ACCEPTED'
    else:
        server_cs = server_cs.upper()
        details += 'SQLNET.CRYPTO_CHECKSUM_SERVER = ' + server_cs

    details += '\n\n'

    l_dict = parse_configfile('listener.ora')
    num_listeners = 0
    num_tcp = 0
    num_tcps = 0

    if l_dict is None:
        details += 'LISTENER.ORA not available.\n'
    else:
        l_protocols = get_listener_protocols(l_dict)

        if len(l_protocols) == 0:
            details += 'No valid listeners found.\n'
        else:
            num_listeners = len(l_protocols)
            details += 'Examined ' + \
                       sing_plural(num_listeners, 'listener.', 'listeners.')
            details += '\n\n'

            for x in l_protocols:
                listener = x[0]
                proto = x[1]
                details += listener + ': '
                details += 'IPC (%d), ' % proto['IPC']
                details += 'TCP (%d), ' % proto['TCP']
                details += 'TCPS (%d)' % proto['TCPS']
                details += '\n'
                num_tcp +=  proto['TCP']
                num_tcps += proto['TCPS']

    details += '\n'
    ssl_cert_revoc = dict.get('SSL_CERT_REVOCATION')
    if ssl_cert_revoc is None:
        details += 'SSL_CERT_REVOCATION is not set (default value = NONE).'
        ssl_cert_revoc = 'NONE'
    else:
        ssl_cert_revoc = ssl_cert_revoc.upper()
        details += 'SSL_CERT_REVOCATION = ' + ssl_cert_revoc

    if server_enc != 'REJECTED':
        if server_enc == 'REQUIRED':
            summary += 'Native encryption is fully enabled. '
        else:
            summary += 'Native encryption is accepted but not required. '
            severity = sat.SEV_MEDIUM

        if server_cs == 'REQUIRED':
            summary += 'Integrity check using checksums is ' + \
                           'fully enabled.'
        elif server_cs == 'REJECTED':
            summary += 'Integrity check using checksums is '+ \
                       'not enabled.'
            severity = max(severity, sat.SEV_LOW)
        else:
            summary += 'Integrity check using checksums is ' + \
                       'accepted but not required.'
            severity = max(severity, sat.SEV_LOW)
    elif num_tcps > 0:
        if num_tcp == 0:
            summary += 'TLS encryption is fully enabled. '
        else:
            summary += 'TLS encryption is enabled on some ports. '
            severity = sat.SEV_MEDIUM

        if ssl_cert_revoc == 'REQUIRED':
            summary += 'Certificate revocation check is ' + \
                                   'fully enabled.'
        elif ssl_cert_revoc == 'NONE':
            summary += 'Certificate revocation check is disabled.'
            severity = max(severity, sat.SEV_LOW)
        else:
            summary += 'Certificate revocation check is ' + \
                                   'requested but not required.'
            severity = max(severity, sat.SEV_LOW)
    else:
        if num_tcp > 0:
            summary += 'Neither native encryption nor TLS ' + \
                                   'encryption is used.'
            severity = sat.SEV_MEDIUM
        else:
            summary += 'Native encryption is not enabled. '
            severity = sat.SEV_MEDIUM

            if server_cs == 'REQUIRED':
                summary += 'Integrity check using ' + \
                           'checksums is fully enabled.'
            elif server_cs == 'REJECTED':
                summary += 'Integrity check using checksums is not enabled.'
            else:
                summary += 'Integrity check using checksums is ' + \
                            'accepted but not required.'

#    remarks = 'Network encryption protects the confidentiality and ' + \
#    'integrity of communication between the database server and ' + \
#    'its clients. Either Native Encryption or TLS should be ' + \
#    'configured to ensure that the connections from ' + \
#    'clients are encrypted. For ' + \
#    'Native Encryption, both ENCRYPTION_SERVER and ' + \
#    'CRYPTO_CHECKSUM_SERVER should be set to REQUIRED.  For ease ' + \
#    'of deployment and compatibility, Oracle Database servers and ' + \
#    'clients are set to ACCEPT encrypted connections out of the ' + \
#    'box. This means that you can enable the desired encryption ' + \
#    'and integrity settings for a connection pair by configuring ' + \
#    'just one side of the connection, server-side or client-side. ' + \
#    'So, for example, if there are many Oracle clients connecting ' + \
#    'to an Oracle database instance, you can configure the required ' + \
#    'encryption and integrity settings for all these connections ' + \
#    'by making the appropriate sqlnet.ora changes at the server ' + \
#    'end. You do not need to implement configuration changes for ' + \
#    'each client separately. However, in this case, the risk of ' + \
#    'having plaintext data passed over the network still exists. ' + \
#    'Keep in mind that whether the security service is enabled or ' + \
#    'not it is based on a combination of client and server ' + \
#    'configuration parameters.  If TLS is used, TCPS should be ' + \
#    'specified for all network ports and SSL_CERT_REVOCATION ' + \
#    'should be set to REQUIRED. '
    remarks = 'ネットワークの暗号化は、データベース・サーバとそのクライアントとの間の通信の機密' + \
        '性と完全性を保護します。' + \
        'クライアントからの接続が確実に暗号化されるように、ネイティブ暗号化またはTLSを設定する必要があります。' + \
        'ネイティブ暗号化の場合は、ENCRYPTION_SERVERとCRYPTO_CHECKSUM_SERVERの両方をREQUIREDに設定する必要があります。' + \
        '配置と互換性を容易にするために、Oracle Databaseのサーバーとクライアントは、暗号化された接続をそのまま使用するように設定されています。' + \
        'つまり、接続の片側（サーバー側またはクライアント側）のみを構成することで、接続ペアに対して望まれる暗号化および整合性設定を有効にできます。' + \
        'したがって、たとえば、Oracleデータベース・インスタンスに接続するOracleクライアントが多数ある場合は、' + \
        'サーバー側で適切なsqlnet.oraを変更することによって、これらすべての接続に必要な暗号化および整合性設定を構成できます。' + \
		'各クライアントに対して個別に設定変更を実施する必要はありません。' + \
		'ただし、この場合、平文データがネットワークを経由するリスクがあります。' + \
		'セキュリティサービスを有効にするかどうかは、クライアントとサーバーの構成パラメータの組み合わせに基づいていることに注意してください。' + \
		'TLSを使用する場合は、すべてのネットワークポートにTCPSを指定し、SSL_CERT_REVOCATIONをREQUIREDに設定する必要があります。'

    refs = {'STIG': 'Rule SV-75937r2, SV-76035r5, SV-76165r1, SV-76193r2, ' + \
                    'SV-76195r2, SV-76203r4, SV-76205r4, SV-76231r3, ' + \
                    'SV-76233r2, SV-76239r1, SV-76241r1, SV-76305r4'}

#    sat.finding('Network Encryption', 'NET.CRYPT', summary,
#        severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('ネットワーク暗号化'.decode('utf-8'), 'NET.CRYPT', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def sqlnet_tcp_nodes(dict):
    severity = sat.SEV_OK

    issue, details = network_parameter(dict=dict,
                                       para_name='TCP.VALIDNODE_CHECKING',
                                       unset_ok=True,
                                       default_value='NO',
                                       required_value='YES')

    if issue:
        summary = 'Valid node check is not enabled, can accept connections ' +\
                  'from any client. '
        severity = sat.SEV_LOW
    else:
        summary = 'Valid node check is enabled, only permitted clients can ' +\
                  'connect. '

    inv_nodes = dict.get('TCP.INVITED_NODES')
    if inv_nodes is None:
        details += 'TCP.INVITED_NODES is not set.\n'
    else:
         details += 'TCP.INVITED_NODES=' + to_string(inv_nodes) + '\n'
    exc_nodes = dict.get('TCP.EXCLUDED_NODES')
    if exc_nodes is None:
        details += 'TCP.EXCLUDED_NODES is not set.\n'
    else:
        details += 'TCP.EXCLUDED_NODES=' + to_string(exc_nodes) + '\n'

    if inv_nodes is None and exc_nodes is None:
        severity = sat.SEV_MEDIUM
        summary += 'Neither TCP.INVITED_NODES nor TCP.EXCLUDED_NODES is set.'
    elif inv_nodes and exc_nodes:
        severity = sat.SEV_LOW
        summary += 'Both TCP.INVITED_NODES and TCP.EXCLUDED_NODES are set.'
    else:
        summary += 'TCP.INVITED_NODES or TCP.EXCLUDED_NODES is set.'

#    remarks = 'TCP.VALIDNODE_CHECKING should be enabled to control which ' + \
#        'client nodes can connect to the database server. ' + \
#        'Either a whitelist of client nodes(IP Address/Hostname/Subnet) ' + \
#        'allowed to connect (TCP.INVITED_NODES) or a blacklist ' + \
#        'of nodes that are not allowed (TCP.EXCLUDED_NODES) ' + \
#        'may be specified. Configuring both lists ' + \
#        'is an error; only the invited node list will be used in this case.'
    remarks = 'TCP.VALIDNODE_CHECKINGは、クライアント・ノードがデータベースサーバに接続できるか' + \
        'を制御するために利用します。' + \
        '接続を許可するクライアント・ノード(IPアドレス/ホスト名/サブネット)のホワイトリスト（TCP.INVITED_NODESにより指定）' + \
        'または、接続を許可しないノードのブラックリスト（TCP.EXCLUDED_NODESにより指定）を指定することができます。' + \
        '両方のリストを設定するとエラーになります。この場合、招待ノードリストのみが使用されます。'
    refs = {'STIG': 'Rule SV-75985r1, SV-76005r2, SV-76305r4' }

#    sat.finding('Client Nodes', 'NET.CLIENTS', summary,
#        severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('クライアント・ノード'.decode('utf-8'), 'NET.CLIENTS', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def sqlnet_banner(dict):
    issue1, det1 = network_parameter(dict=dict,
                                     para_name='SEC_USER_AUDIT_ACTION_BANNER',
                                     case_sensitive=True)
    issue2, det2 = network_parameter(dict=dict,
                               para_name='SEC_USER_UNAUTHORIZED_ACCESS_BANNER',
                               case_sensitive=True)
    severity = sat.SEV_UNKNOWN
    if issue1 or issue2:
        summary = 'Connect banners are not fully configured.'
    else:
        summary = 'Connect banners are configured.'

    details = det1 + det2
    remarks = 'These banner messages are used to warn connecting users ' + \
        'that unauthorized access is not permitted and that ' + \
        'their activities may be audited.'

    sat.finding('SQLNET Banners', 'NET.BANNER', summary,
        severity=severity, details=details, remarks=remarks)

def listener_ora():
    dict = parse_configfile('listener.ora')
    if dict is None:
        sat.diag('Skipped LISTENER Parameters')
        return

    lsnr_cost_parameter(dict)
    lsnr_logging_listener_name(dict)

def lsnr_cost_parameter(dict):
    list = get_listeners(dict)
    good = []
    bad = []
    sub_details = ''
    severity = sat.SEV_OK

    for lsnr in list:
        lsnr_name = lsnr.upper()
        sub_details += 'Parameter setting for ' + lsnr_name + ':\n'

        para_name = 'ADMIN_RESTRICTIONS_' + lsnr_name
        admin_issue, det = network_parameter(dict=dict,
                                          para_name=para_name,
                                          unset_ok=True,
                                          default_value='OFF',
                                          required_value='ON')
        sub_details += det

        para_name = 'DYNAMIC_REGISTRATION_' + lsnr_name
        dr_issue, det = network_parameter(dict=dict,
                                          para_name=para_name,
                                          unset_ok=True,
                                          default_value='ON',
                                          required_value='OFF')
        sub_details += det

        para_name = 'VALID_NODE_CHECKING_REGISTRATION_' + lsnr_name
        vncr_issue, det = network_parameter(dict=dict,
                                          para_name=para_name,
                                          unset_ok=True,
                                          default_value='OFF',
                                          forbidden_value='OFF')
        sub_details += det

        para_name = 'SECURE_PROTOCOL_' + lsnr_name
        sec_pro = dict.get(para_name)
        if sec_pro is None:
            sub_details += para_name + ' is not set.\n'
        else:
            sub_details += para_name + '=' + join_list(sec_pro) + '\n'

        para_name = 'SECURE_CONTROL_' + lsnr_name
        sec_con = dict.get(para_name)
        if sec_con is None:
            sub_details += para_name + ' is not set.\n'
        else:
            sub_details += para_name + '=' + join_list(sec_con) + '\n'

        para_name = 'SECURE_REGISTER_' + lsnr_name
        sec_reg = dict.get(para_name)
        if sec_reg is None:
            sub_details += para_name + ' is not set.\n'
        else:
            sub_details += para_name + '=' + join_list(sec_reg) + '\n'

        sub_details += '\n'

        para_name = 'CONNECTION_RATE_' + lsnr_name
        con_rate = dict.get(para_name)
        if sec_reg is None:
            sub_details += para_name + ' is not set.\n'
        else:
            sub_details += para_name + '=' + join_list(con_rate) + '\n'

        sub_details += '\n'


        if not admin_issue and (not dr_issue or not vncr_issue or \
        (sec_pro or (sec_con and sec_reg))):
            good.append(lsnr_name)
        else:
            bad.append(lsnr_name)

    if len(bad) > 0:
        severity = sat.SEV_MEDIUM

    summary, details = listener_summary(good, bad)
    details += '\n' + sub_details

#    remarks = 'These parameters are used to limit changes to ' + \
#        'the network listener configuration. ' + \
#        'ADMIN_RESTRICTIONS should be enabled to prevent ' + \
#        'parameter changes to the running listener. ' + \
#        'One of the following ' + \
#        'restrictions on service registration should be implemented: ' + \
#        '(a) prevent changes by disabling DYNAMIC_REGISTRATION, ' + \
#        '(b) limit the nodes that can make changes by enabling ' + \
#        'VALID_NODE_CHECKING_REGISTRATION, or ' + \
#        '(c) limit the network sources for changes using the COST ' + \
#        'parameters SECURE_PROTOCOL, SECURE_CONTROL, and SECURE_REGISTER. ' + \
#        'CONNECTION_RATE determines rate enforced across all the ' + \
#        'endpoints that are rate limited.'
    remarks = 'これらのパラメータは、ネットワーク・リスナーの設定の変更を制限するために使用され' + \
        'ます。実行しているリスナーのパラメータ変更を防ぐためにADMIN_RESTRICTIONSを有効にすべきです。' + \
        '次のような制約の一つが実装されるべきです。 (a) DYNAMIC_REGISTRATIONの無' + \
		'効化にすることで変更を防止する (b)VALID_NODE_CHECKING_REGISTRATIONを有効にする' + \
        'ことでノードが変更できることを制限する (c)SECURE_CONTROL、SECURE_PROTOCOL、SECU' + \
        'RE_REGISTERのCOSTパラメータを使いネットワーク・ソースの変更を制限する。 ' + \
		'CONNECTION_RATEは、レート制限されているすべてのエンドポイントに適用されるレートを決定します。'

    refs = {'CIS': 'Recommendation 2.1.1, 2.1.3, 2.1.4',
            'STIG': 'Rule SV-76273r1, SV-76305r4 '}

#    sat.finding('Network Listener Configuration', 'NET.COST', summary,
#        severity, details, remarks, refs)
    sat.finding('ネットワーク・リスナー構成'.decode('utf-8'), 'NET.COST', summary,
        severity, details, remarks.decode('utf-8'), refs)

def lsnr_logging_listener_name(dict):
    good = []
    bad = []
    severity = sat.SEV_OK
    sub_details = ''

    for lsnr in get_listeners(dict):
        lsnr_name = lsnr.upper()

        para_name = 'LOGGING_' + lsnr_name
        issue, det = network_parameter(dict=dict,
                                       para_name=para_name,
                                       unset_ok=True,
                                       default_value='ON',
                                       required_value='ON')

        sub_details += 'Parameter setting for ' + lsnr_name + ':\n'
        sub_details += det

        if issue:
            bad.append(lsnr_name)
        else:
            good.append(lsnr_name)

    if len(bad) > 0:
        severity = sat.SEV_LOW

    summary, details = listener_summary(good, bad)
    details += '\n' + sub_details

#    remarks = 'This parameter enables logging of listener activity. ' + \
#        'Log information can be useful for troubleshooting and ' + \
#        'to provide early warning of attempted attacks.'
    remarks = 'このパラメータは、リスナーのアクティビティのログを有効にします。ログの情報は、ト' + \
        'ラブルシューティングやリスナーへの攻撃の早期検知に役立ちます。'

#    sat.finding('Listener Logging Control', 'NET.LISTENLOG', summary=summary,
#        severity=severity, details=details, remarks=remarks)
    sat.finding('リスナーログ制御'.decode('utf-8'), 'NET.LISTENLOG', summary=summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'))

def network_parameter(dict, para_name, unset_ok=False, default_value=None,
                      required_value=None, forbidden_value=None,
                      case_sensitive=False):
    details = ''
    issue_found = False
    input_value = ''

    if para_name not in dict:
        if not unset_ok:
            details = para_name + ' is not set. '
            details += 'Should be set to a proper value.\n'
            issue_found = True
            return issue_found, details

        if default_value is not None:
            input_value = default_value
            details = para_name + ' is not set '
            details += '(default value = ' + default_value + ')'
    else:
        input_value = to_string(dict[para_name])
        if not case_sensitive:
            input_value = input_value.upper()
        details += para_name + '=' + input_value

    if required_value is not None and input_value != required_value:
        details += '. Recommended value is %s.\n' % required_value
        issue_found = True
    elif forbidden_value is not None and input_value == forbidden_value:
        details += '. Should not be set to %s.\n' % forbidden_value
        issue_found = True
    else:
        details += '.\n'

    return issue_found, details

def listener_summary(good_list, bad_list):
    total = len(good_list) + len(bad_list)
    summary = 'Examined ' + sing_plural(total, 'listener. ', 'listeners. ') + \
              'Found ' + sing_plural(len(bad_list), 'listener', 'listeners') + \
              ' not configured properly.' 
    details = ''
    if len(good_list) > 0:
        details += 'Listeners configured properly: ' + \
            join_list(good_list) + '\n'
    if len(bad_list) > 0:
        details += 'Listeners not configured properly: ' + \
            join_list(bad_list) + '\n'
    return summary, details

def get_protocol_from_address(address, proto_count):
    protocol = address.get('PROTOCOL')

    if protocol is None:
        return proto_count
    else:
        protocol = protocol.upper()

    if protocol in ('IPC', 'TCP', 'TCPS'):
        proto_count[protocol] += 1

    return proto_count

def collect_protocols(dict, proto_count):
    for k, v in dict.items():
        if k == 'ADDRESS':
            if type(v) == type([]):
                for x in v:
                    proto_count = get_protocol_from_address(x, proto_count)
                continue

            protcocols = get_protocol_from_address(v, proto_count)
        elif type(v) == type({}):
            proto_count = collect_protocols(v, proto_count)
        elif type(v) == type([]):
            for x in v:
                proto_count = collect_protocols(x, proto_count)
        else:
            continue

    return proto_count

def get_listener_protocols(dict):
    result = []

    for k, v in dict.items():
        if k.startswith('SID_LIST_'):
            continue

        if type(v) != type({}):
            continue

        proto_count = {'IPC': 0, 'TCP': 0, 'TCPS': 0}
        proto_count = collect_protocols(v, proto_count)

        if sum(proto_count.values()) > 0:
            result.append([k, proto_count])

    return result

def contains_key(struct, keywords):
    if type(struct) == dict:
        for k, v in struct.items():
            if k in keywords:
                return True
            elif contains_key(v, keywords):
                return True
        return False
    elif type(struct) == list:
        for elem in struct:
            if contains_key(elem, keywords):
                return True
        return False
    else:
        return False

def get_listeners(dict):
    listener_list = []
    for k, v in dict.items():
        if contains_key(v, ('ADDRESS', 'ADDRESS_LIST')):
            listener_list.append(k)

    return listener_list


def os_authentication_user():
    data_group = sat.get_data('os_group_file', 1)
    if data_group is None:
        sat.diag('Skipped OS Authentication')
        return None

    data_dba = sat.get_data('osdba_group', 1)
    mem_dba, details_dba = os_group_members('SYSDBA', data_dba)
    all_group_users = list(mem_dba)

    details_opr = ''
    details_bkp = ''
    details_km = ''
    details_dg = ''
    details_rac = ''

    if target_db_version >= '11':
        data_opr = sat.get_data('sysoper_group', 1)
        data_bkp = sat.get_data('sysbackup_group', 1)
        data_km  = sat.get_data('syskm_group', 1)
        data_dg  = sat.get_data('sysdg_group', 1)
        data_rac = sat.get_data('sysrac_group', 1)
        mem_opr, details_opr = os_group_members('SYSOPER', data_opr)
        mem_bkp, details_bkp = os_group_members('SYSBACKUP', data_bkp)
        mem_km,  details_km  = os_group_members('SYSKM', data_km)
        mem_dg,  details_dg  = os_group_members('SYSDG', data_dg)
        mem_rac, details_rac = os_group_members('SYSRAC', data_rac)
        all_group_users += list(mem_opr + mem_bkp + mem_km  + \
                                        mem_dg  + mem_rac)

    severity=sat.SEV_UNKNOWN
    details_rootpriv = ''
    mem_root, details_root = os_group_members('ROOT', [["root"]])
    mem_sudo, details_sudo = os_group_members('SUDO', [["sudo"]])
    all_priv_os_users = ['root'] + list(mem_root + mem_sudo)
    root_dba_users =[]
    for grp in all_priv_os_users:
      if grp and any(grp in s for s in all_group_users):
          root_dba_users.append(grp)

    if len(root_dba_users) > 0:
       details_rootpriv += sing_plural(len(root_dba_users), 'user', 'users') +\
                          ' with ROOT privileges being used as DBA account: '+\
                           ', '.join(root_dba_users)
       severity = sat.SEV_HIGH

    total_num = len(set(filter(None,all_group_users)))

    summary = sing_plural(total_num, 'OS user', 'OS users') + \
              ' can connect to the database via OS authentication.'

    details = details_dba + details_opr + details_bkp + \
                  details_km + details_dg + details_rac + details_rootpriv
    refs =  {'STIG': 'Rule SV-75977r1, SV-76027r1'} 
#    remarks = 'OS authentication allows operating system users within ' + \
#        'the specified user group to connect to the database ' + \
#        'with administrative privileges without any further authentication. '+\
#        'This shows the OS group names and users that ' + \
#        'can exercise each administrative privilege. ' + \
#        'OS users with administrative privileges should be reviewed ' + \
#        'to prevent any unauthorized, malicious or unintentional access ' + \
#        'to the database.'
    remarks = 'OS認証により指定されたユーザグループ内のOSユーザーがそれ以上の認証なしで管理者権限でデータベースに接続' + \
        'することができます。ここではそれぞれの各管理者権限を行使することができるOSのグル' + \
        'ープ名とユーザを表示しています。' + \
		'データベースへの許可されていない、悪意のある、または意図しないアクセスを防ぐために、' + \
		'管理者権限を持つOSユーザーを確認する必要があります。'

#    sat.finding('OS Authentication', 'OS.AUTH', summary,
#        severity, details=details, remarks=remarks, refs=refs)
    sat.finding('OS認証'.decode('utf-8'), 'OS.AUTH', summary,
        severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def check_pmon_proc():
    proclist = find_processes('pmon')
    if proclist is None:
        sat.diag('Skipped PMON processes')
        return None

    inst_name = get_from_env_data('ORACLE_SID')

    oh_dir = get_from_env_data('ORACLE_HOME')

    oh_owner = None
    oh_data =  sat.get_data('oracle_home_owner', 1)
    if oh_data is not None:
        oh_owner = oh_data[0][0]

    owners = set([])
    plist = []
    pmon_owner = None
    pmon_proc = None

    for p in proclist:
        owners.add(p['owner'])
        info = '\tOwner: ' + p['owner'] + ', Command: ' + p['command']
        if inst_name is not None and inst_name in p['command']:
            pmon_owner = p['owner']
            pmon_proc = p['command']
        else:
            plist.append(info)

    if pmon_proc is None:
        num_proc = len(plist)
    else:
        num_proc = len(plist) + 1

    summary = 'Found ' + \
              sing_plural(num_proc, 'PMON process. ', 'PMON processes. ')
    details = ''

    if pmon_owner is None or oh_owner is None:
        severity = sat.SEV_UNKNOWN
        sat.diag('Skipped PMON process owner check')
    else:
        if pmon_owner == oh_owner:
            severity = sat.SEV_OK
            summary += 'The owner of the PMON process ' + \
                                  'matches the ORACLE_HOME owner.'
        else:
            severity = sat.SEV_MEDIUM
            summary += 'The owner of the PMON process ' + \
                          'does not match the ORACLE_HOME owner.'

        details = 'PMON process: ' + pmon_proc + ', '
        details += 'Owner: ' + pmon_owner + '\n'
        details += 'ORACLE_HOME owner: ' + oh_owner + '\n'

    if len(plist) > 0:
        details += '\nOther PMON processes found:\n'
        details += join_list(plist, '\n')

#    remarks = 'The PMON process monitors user processes and frees ' + \
#        'resources when they terminate. This process should run ' + \
#        'with the user ID of the ORACLE_HOME owner.'
    remarks = 'PMONプロセスは、ユーザー・プロセスを監視し、それらが終了したときにリソースを解放' + \
        'します。このプロセスは、 ORACLE_HOMEの所有者のユーザーIDで実行する必要があります。'

    refs = {'STIG' : 'Rule SV-76069r1' }

#    sat.finding('Process Monitor Processes', 'OS.PMON', summary,
#        severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('Process Monitorプロセス'.decode('utf-8'), 'OS.PMON', summary,
        severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

    return owners

def pmon_agent_tnslsnr():
    powners = check_pmon_proc()
    aowners, asummary, adetails = process_ps_data('agent', 'Agent')
    lowners, lsummary, ldetails = process_ps_data('tnslsnr', 'Listener')

    aseverity = sat.SEV_OK
    lseverity = sat.SEV_OK

    if powners is None or aowners is None or lowners is None:
        sat.diag('Skipped Agent and Listener process check')
    else:
        overlap = aowners.intersection(powners.union(lowners))
        if len(overlap) == 0:
            asummary += 'Agent process owners ' + \
                  'do not overlap with Listener or PMON ' + \
                  'process owners.'
        else:
            aseverity = sat.SEV_LOW
            asummary = 'Some Agent process owners overlap ' + \
                       'with Listener or PMON process owners.'

        overlap =  lowners.intersection(powners.union(aowners))
        if len(overlap) == 0:
            lsummary += 'Listener process owners ' + \
              'do not overlap with Agent or PMON process owners.'
        else:
            lseverity = sat.SEV_HIGH
            lsummary += 'Some Listener process are owned by' + \
                       'Agent or PMON process owners.'

#    remarks = 'Agent processes are used by Oracle Enterprise Manager ' + \
#        'to monitor and manage the database. These processes ' + \
#        'should run with a user ID separate from the database ' + \
#        'and listener processes.'
    remarks = 'エージェント・プロセスは、データベースの監視および管理するためにOracle Enterpris' + \
        'e Managerで使用されています。これらのプロセスは、データベースおよびリスナープロ' + \
        'セスとは別のユーザーIDで実行する必要があります。'

    if asummary is not None:
        sat.finding('エージェント・プロセス'.decode('utf-8'), 'OS.AGENT',
                    summary=asummary, severity=aseverity, details=adetails,
                    remarks=remarks.decode('utf-8'))

    lsnr_pwd = sat.get_data('lsnr_stat',1)
    if lsnr_pwd is not None:
       lseverity = sat.SEV_LOW
       ldetails += 'Security for Listener not set to Local OS Authentication. '

#    remarks = 'Listener processes accept incoming network connections ' + \
#        'and connect them to the appropriate database server ' + \
#        'process. These processes should run with a user ID ' + \
#        'separate from the database and agent processes. ' + \
#        'These processes should be administered only through ' + \
#        'local OS authentication.'
    remarks = 'リスナー・プロセスは、データベースへの接続要求を受け入れ、適切なデータベース・サーバー・プ' + \
        'ロセスに接続します。これらのプロセスは、データベースおよびエージェントプロ' + \
        'セスとは別のユーザーIDで実行する必要があります。' + \
		'これらのプロセスは、ローカルOS認証を通じてのみ管理されるべきです。'

    refs = { 'STIG': 'Rule SV-75931r1' }

    if lsummary is not None:
        sat.finding('リスナー・プロセス'.decode('utf-8'), 'OS.LISTEN',
                    summary=lsummary, severity=lseverity, details=ldetails,
                    remarks=remarks.decode('utf-8'), refs=refs)

def db_file_permission():
    severity = sat.SEV_OK
    summary = ''
    details = ''

    oh_owner_data = sat.get_data('oracle_home_owner', 1)
    oh_owner = ''
    if oh_owner_data is not None and len(oh_owner_data) > 0:
        oh_owner = oh_owner_data[0][0]

    dbs_file_num, dbs_dir_num, dbs_file_perm_list, \
        dbs_dir_perm_list, dbs_file_owner_list = \
          file_permission(name='dbs_file_permission',
                          diag_msg='Skipped DBS File Permissions',
                          max_perms=int('660', 8), prefix_path='dbs')

    bin_file_num, bin_dir_num, bin_file_perm_list, \
        bin_dir_perm_list, bin_file_owner_list = \
          file_permission(name='executable_permission',
                          diag_msg='Skipped Executable File Permissions',
                          max_perms=int('755', 8), prefix_path='bin')

    sqlnet_file_num, sqlnet_dir_num, sqlnet_file_perm_list, \
        sqlnet_dir_perm_list, sqlnet_file_owner_list = \
          file_permission(name='ls_sqlnet.ora',
                          diag_msg='Skipped SQLNET.ORA Permission',
                          max_perms=int('664', 8))

    lsnr_file_num, lsnr_dir_num, lsnr_file_perm_list, \
        lsnr_dir_perm_list, lsnr_file_owner_list = \
          file_permission(name='ls_listener.ora',
                          diag_msg='Skipped LISTENER.ORA Permission',
                          max_perms=int('664', 8))

    lib_file_num, lib_dir_num, lib_file_perm_list, \
        lib_dir_perm_list, lib_file_owner_list = \
          file_permission(name='library_permission',
                          diag_msg='Skipped Library File Permissions',
                          max_perms=int('755', 8), prefix_path='lib')

    total = dbs_file_num + dbs_dir_num + \
                bin_file_num + bin_dir_num + \
                sqlnet_file_num + sqlnet_dir_num + \
                lsnr_file_num + lsnr_dir_num + \
                lib_file_num + lib_dir_num 

    if total == 0:
        return

    total_errors = len(dbs_file_perm_list) + len(dbs_dir_perm_list) + \
                   len(dbs_file_owner_list) + len(bin_file_perm_list) + \
                   len(bin_dir_perm_list) + len(bin_file_owner_list) + \
                   len(sqlnet_file_perm_list) + len(sqlnet_dir_perm_list) + \
                   len(sqlnet_file_owner_list) + len(lsnr_file_perm_list) + \
                   len(lsnr_dir_perm_list) + len(lsnr_file_owner_list) + \
                   len(lib_file_perm_list) + len(lib_dir_perm_list) + \
                   len(lib_file_owner_list)

    dir_total = dbs_dir_num + bin_dir_num + lib_dir_num
    dir_errors = len(dbs_dir_perm_list) + len(bin_dir_perm_list) + \
                     len(sqlnet_dir_perm_list) + len(lsnr_dir_perm_list) + \
                     len(lib_dir_perm_list)

    bin_total = bin_file_num
    bin_errors = len(bin_file_perm_list)

    config_total = sqlnet_file_num+lsnr_file_num;
    config_errors = len(sqlnet_file_perm_list) + len(lsnr_file_perm_list)

    data_file_total = dbs_file_num
    data_file_errors = len(dbs_file_perm_list)

    lib_total = lib_file_num
    lib_errors = len(lib_file_perm_list)

    summary = 'Examined ' + sing_plural(total, 'file. ', 'files. ') + \
              'Found ' + sing_plural(total_errors, 'error.', 'errors.')

    if total_errors > 0:
        severity = sat.SEV_MEDIUM

    oh_dir = get_from_env_data('ORACLE_HOME')
    if oh_dir is not None:
        details = 'ORACLE_HOME: ' + oh_dir + '\n'

    details += 'ORACLE_HOME owner: %s \n' % oh_owner + \
               'Directories: %d (%d permission errors) \n' % \
                   (dir_total, dir_errors) + \
               'Executables in $ORACLE_HOME/bin: ' \
                   '%d (%d permission errors) \n' % \
                   (bin_total, bin_errors) + \
               'Configuration files in $TNS_ADMIN: ' \
                   '%d (%d permission errors) \n' % \
                   (config_total, config_errors) + \
               'Data files in $ORACLE_HOME/dbs: ' \
                   '%d (%d permission errors) \n' % \
                   (data_file_total, data_file_errors) + \
               'Libraries in $ORACLE_HOME/lib: ' \
                   '%d (%d permission errors) \n\n' % \
                   (lib_total, lib_errors) 


    file_perm_list = dbs_file_perm_list + bin_file_perm_list + \
                         sqlnet_file_perm_list + lsnr_file_perm_list + \
                         lib_file_perm_list

    if len(file_perm_list) > 0:
        details += db_file_detail('Files with permission errors',
                                      file_perm_list)
    dir_perm_list = dbs_dir_perm_list + bin_dir_perm_list + \
                        sqlnet_dir_perm_list + lsnr_dir_perm_list + \
                        lib_dir_perm_list

    if len(dir_perm_list) > 0:
        details += db_file_detail('Directories with permission errors',
                                      dir_perm_list)

    file_owner_list = dbs_file_owner_list + bin_file_owner_list + \
                          sqlnet_file_owner_list + lsnr_file_owner_list + \
                          lib_file_owner_list

    if len(file_owner_list) > 0:
        details += \
                  db_file_detail('Files or directories with unexpected owner',
                             file_owner_list)

#    remarks = 'The ORACLE_HOME directory and its subdirectories contain ' +\
#                'files that are critical to the correct operation of the ' +\
#                'database, including executable programs, libraries, data ' +\
#                'files, and configuration files. Operating system file ' + \
#                'permissions must not allow these files to be modified by ' + \
#                'users other than the ORACLE_HOME owner and must not allow '+ \
#                'other users to directly read the contents of Oracle data files.'
    remarks = 'ORACLE_HOMEディレクトリとそのサブディレクトリには、実行可能プログラム、ライブラリ、データフ' + \
        'ァイル、および構成ファイルを含むデータベースの正しい動作に重要であるファイルが含' + \
        'まれています。' + \
        'オペレーティングシステムファイルのアクセス権は、ORACLE_HOMEの所有者以外のユーザ' + \
        'ーがこれらのファイルを変更することを許可してはいけません。同様に、他のユーザーが' + \
        '直接Oracleデータファイルの内容を読み取ることも許可すべきではありません。'

    refs = { 'STIG': 'Rule SV-76001r1, SV-76277r1, SV-76359r1, SV-76365r1' }

#    sat.finding('File Permissions in ORACLE_HOME', 'OS.FILES',
#        summary, severity=severity, details=details, remarks=remarks, refs=refs)
    sat.finding('ORACLE_HOMEのファイル・パーミッション'.decode('utf-8'), 'OS.FILES',
        summary, severity=severity, details=details, remarks=remarks.decode('utf-8'), refs=refs)

def find_processes(cmdname):
    data = sat.get_data('processes', 1)
    if data is None or len(data) == 0:
        return None

    proclist = []
    cmd_index = data[0][0].find('COMMAND')
    if cmd_index < 0:
        cmd_index = data[0][0].find('CMD')
    for x in data:
        if re.search(cmdname, x[0]):
            fields = x[0].split()
            user = fields[0]
            if cmd_index >= 0:
                cmd = x[0][cmd_index:]
            else:
                cmd = ' '.join(fields[1:])
            proclist.append({'owner': user, 'command': cmd})
    return proclist

def process_ps_data(cmdname, pname):
    proclist = find_processes(cmdname)
    if proclist is None:
        sat.diag('Skipped ' + pname + ' processes')
        return None, None, None

    owners = set()
    if len(proclist) > 0:
        summary = 'Found ' + sing_plural(len(proclist), pname + ' process. ', 
                                                        pname + ' processes. ')
        list = []
        for p in proclist:
            owners.add(p['owner'])
            info = 'Owner: ' + p['owner'] + '\nCommand: ' + p['command']
            list.append(info)
        details = join_list(list, '\n\n')
    else:
        summary = 'No ' + pname + ' processes found. '
        details = ''

    return owners, summary, details

def get_from_env_data(keyword):
    data = sat.get_data('environment', 1)
    if data is None:
        return None

    value = None
    for x in data:
        keyval = x[0].split('=')
        if keyword == keyval[0]:
            value = keyval[1]
            break
    return value

def decode_ls_data(data):
    rows = []

    for x in data:
        fields = x[0].split()

        if len(fields) != 9:
            continue

        rows.append([fields[0][0:10], fields[2], fields[3], fields[-1]])

    return rows

def capped_perms(perm, max_perms):
    capped = ''
    n = len(perm) - 1
    for i in range(len(perm)):
        if max_perms & 1<<(n-i):
            capped += perm[i]
        else:
            capped += '-'
    return capped

def file_permission(name, diag_msg, max_perms, prefix_path=None):
    file_perm_list = []
    dir_perm_list = []
    file_owner_list = []
    num_file = 0
    num_dir = 0
    path = ''
    if prefix_path is not None:
        path = prefix_path + '/'

    data = sat.get_data(name, 1)

    if data is None or len(data) == 0:
        sat.diag(diag_msg)
        return num_file, num_dir, file_perm_list, \
                   dir_perm_list, file_owner_list

    oh_owner_data = sat.get_data('oracle_home_owner', 1)
    oh_owner = ''
    if oh_owner_data is not None and len(oh_owner_data) > 0:
        oh_owner = oh_owner_data[0][0]

    rows = decode_ls_data(data)
    for x in rows:
        perms = x[0]
        if perms[0] == '-':
            num_file += 1
            capped = capped_perms(perms[1:], max_perms)
            if capped != perms[1:]:
                file_perm_list.append('%s (%s should be %s)' %
                    (path + x[3], perms[1:], capped))
        elif perms[0] == 'd' and x[3] != '..':
            num_dir += 1
            capped = capped_perms(perms[1:], int('775', 8))
            if capped != perms[1:]:
                dir_perm_list.append('%s (%s should be %s)' %
                    (path + x[3], perms[1:], capped))

        if perms[0] not in ['-', 'd']:
            continue

        if len(oh_owner) > 0 and x[1] != oh_owner:
            if not (path == 'bin/' and x[1] == 'root'):
                file_owner_list.append(path + x[3] + ' (owner = ' + x[1] + ')')

    return num_file, num_dir, file_perm_list, dir_perm_list, file_owner_list

def db_file_detail(title, file_list):
    details = title + ':\n'
    details += join_list(file_list, '\n')
    details += '\n\n'
    return details

def os_group_members(db_priv, name_data):
    data_group = sat.get_data('os_group_file', 1)
    details = ''
    mem_list = []

    if name_data is None or len(name_data) != 1:
        return mem_list, details

    os_group = name_data[0][0]

    for y in data_group:
        for z in y:
            items = z.split(':')

            if len(items) == 4 and items.pop(0) == os_group:
                group_members = items.pop()
                mem_list = group_members.split(',')
                group_members = group_members.replace(',', ', ')
                details += db_priv + ' [' + os_group + ' group]: ' + \
                           group_members + '\n'

    return mem_list, details


check_oracle_accts = False

all_users = []
all_roles = []
oracle_users = []
acct_profiles = {}
all_local_users = []
local_acct_profiles = {}

oracle_admin_users = ['SYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC']

collection_date = None

target_db_version = None

sys_param_dict = {}

db_options_dict = {}

def to_string(obj):
    try:
        return unicode(obj)
    except NameError:
        return str(obj)

def enumerate_users():
    global all_users, all_roles, oracle_users, acct_profiles, all_local_users, local_acct_profiles

    default_oracle_users = ['SYS', 'SYSTEM', 'GSMCATUSER', \
        'XS$NULL', 'MDDATA', 'REMOTE_SCHEDULER_AGENT',\
        'DBSFWUSER', 'SYSBACKUP', 'GSMUSER', \
        'APEX_PUBLIC_USER', 'SYSRAC', 'CTXSYS', \
        'OJVMSYS', 'DVF', 'DVSYS', 'AUDSYS', 'DIP', \
        'SPATIAL_WFS_ADMIN_USR', 'LBACSYS', 'SYSKM', \
        'OUTLN', 'ORACLE_OCM', 'SYS$UMF', \
        'SPATIAL_CSW_ADMIN_USR', 'SYSDG', 'DBSNMP', \
        'APPQOSSYS', 'GGSYS', 'ANONYMOUS', \
        'FLOWS_FILES', 'SI_INFORMTN_SCHEMA', \
        'GSMADMIN_INTERNAL', 'ORDPLUGINS', \
        'APEX_050000', 'MDSYS', 'OLAPSYS', 'ORDDATA', \
        'XDB', 'WMSYS', 'ORDSYS', 'EXFSYS', 'TSMSYS', \
        'SCOTT', 'ADAMS', 'JONES', 'CLARK', 'BLAKE', \
        'HR', 'OE', 'SH', 'AWR_STAGE', 'CSMIG', 'DMSYS', \
        'PERFSTAT', 'TRACESVR', 'IX', 'PM', 'HTTP_REDIRECT',
        'XS$NULL']
    excluded_users = ['XS$NULL']

    user_data = sat.get_data('user_account', 1)
    if user_data is None:
        sat.diag('User list not available')
    else:
        name = sat.get_index('user_account', 'username')
        acct_status = sat.get_index('user_account', 'status')
        user_prof = sat.get_index('user_account', 'profile')
        is_oracle = sat.get_index('user_account', 'oracle_supplied')
        is_common = sat.get_index('user_account', 'common')

        oracle_users = set(default_oracle_users)
        if is_oracle is not None:
            oracle_users.update([x[name] for x in user_data if x[is_oracle]])

        for x in user_data:
            if (x[name] not in excluded_users and
            (check_oracle_accts or
             x[acct_status] == 'OPEN' or
             x[name] not in oracle_users)):
                all_users.append(x[name])
                acct_profiles[x[name]] = x[user_prof]
                if is_common is not None and x[is_common] == 'NO':
                   all_local_users.append(x[name])
                   local_acct_profiles[x[name]] = x[user_prof]

    role_data = sat.get_data('roles', 1)

    if role_data is None:
        sat.diag('Role list not available')
    else:
        name = sat.get_index('roles', 'role')
        all_roles = [x[name] for x in role_data]

def populate_globals():
    sat.add_reference('CIS', 'CIS Oracle Database 12c Benchmark v2.0.0')
    sat.add_reference('GDPR', 'EU GDPR 2016/679')
    sat.add_reference('STIG', 'Oracle Database 12c STIG  v1 r10')

    global sys_param_dict
    data = sat.get_data('parameters', 1)
    if data is None:
        sat.diag('System parameters not available')
    else:
        name = sat.get_index('parameters', 'name')
        value = sat.get_index('parameters', 'value')
        for x in data:
            sys_param_dict[x[name].upper()] = to_string(x[value])

    global db_options_dict
    data = sat.get_data('option_check', 1)
    if data is None:
        sat.diag('Database options not available')
    else:
        name = sat.get_index('option_check', 'parameter')
        value = sat.get_index('option_check', 'value')
        for x in data:
            db_options_dict[x[name]] = x[value]
    
    global show_unassigned_roles_privs
    show_unassigned_roles_privs = False

    global target_db_version

    data = sat.get_data('date_and_release', 1)
    if data is not None:
        dbv_idx = sat.get_index('date_and_release', 'release')
        target_db_version = data[0][dbv_idx]
 

def tokenizer(data):
    mylex = shlex.shlex(data)
    mylex.wordchars += '!$%&*+-./:;<>?@[\]^`{|}~ \t'
    mylex.whitespace = '\r\n'
    return mylex

def parse_gettoken(lex):
    while True:
        tok = lex.get_token()
        if not tok:
            return ''
        tok = tok.strip()
        if tok:
            return tok

def parse_expect(lex, expected):
    token = parse_gettoken(lex)
    if expected != token:
        raise Exception('expected %s, found %s' % (expected, token))

def parse_lookahead(lex):
    token = parse_gettoken(lex)
    lex.push_token(token)
    return token

def parse_stmt(lex):
    id = parse_gettoken(lex)
    if id.upper() == 'SET':
        id = parse_gettoken(lex)
    parse_expect(lex, '=')
    value = parse_value(lex)
    return { id.upper(): value }

def parse_value(lex):
    token = parse_gettoken(lex)
    token = token.strip('"')
    if token == '(':
        token1 = parse_gettoken(lex)
        if parse_lookahead(lex) == '=':
            lex.push_token(token1)
            lex.push_token('(')
            value = parse_stmtlist(lex, '(', ')', None)
        else:
            lex.push_token(token1)
            value = parse_idlist(lex)
            parse_expect(lex, ')')
        return value
    elif token == ')':
        lex.push_token(')')
        return ''
    else:
        if parse_lookahead(lex) == '=':
            lex.push_token(token)
            value = parse_stmtlist(lex, None, None, ',')
        else:
            value = token
        return value

def parse_stmtlist(lex, pre, post, between):
    dict = {}
    while True:
        if parse_lookahead(lex) == lex.eof:
            break
        if pre != None:
            parse_expect(lex, pre)
        value = parse_stmt(lex)
        if post != None:
            parse_expect(lex, post)
        merge_dict(dict, value)

        token = parse_lookahead(lex)
        if between != None:
            if token != between:
                break
            parse_expect(lex, between)
        elif pre != None and token != pre:
            break
    return dict

def parse_idlist(lex):
    id = parse_gettoken(lex)
    token = parse_gettoken(lex)
    if token == ',':
        value = parse_idlist(lex)
        return [id] + value
    else:
        lex.push_token(token)
        return [id]

def merge_dict(current, new):
    for key, value in new.items():
        curval = current.get(key, None)
        if curval == None:
            current[key] = value
        else:
            if not isinstance(curval, list):
                current[key] = [curval]
            current[key].append(value)

def parse_configfile(name):
    data = sat.get_data(name, 1)

    if data == None or len(data) == 0:
        return None

    if sys.version_info < (3, 0):
        lines = [x[0].encode('ascii', 'replace') for x in data]
    else:
        lines = [x[0] for x in data]
    mylex = tokenizer('\n'.join(lines))

    try:
        dict = parse_stmtlist(mylex, None, None, None)
        return dict
    except Exception as e:
        sat.diag('Failed to parse ' + name + ': ' + str(e))
        return None

def read_date(date_str, format='%d-%m-%Y %H:%M'):
    try:
        return datetime.datetime.strptime(date_str, format)
    except Exception as e:
        return None

def format_date(input_date, format_str='%a %b %d %Y %X'):
    if input_date is None:
        return ''
    else:
        return input_date.strftime(format_str)

def days_since(input_date):
    if input_date and collection_date:
        return (collection_date - input_date).days
    else:
        return None

def max_date(date1, date2):
    if date1 is None:
        return date2
    elif date2 is None:
        return date1
    else:
        if isinstance(date1, datetime.date) and \
           isinstance(date2, datetime.date):
           return max(date1, date2)
        elif isinstance(date1, datetime.date):
           return date1
        elif isinstance(date2, datetime.date):
           return date2
        else:
           return None

def join_list(str_list, sep=', '):
    if str_list:
        if type(str_list) == list or type(str_list) == tuple:
            return sep.join(str_list)
        else:
            return str_list
    else:
        return '(none)'

def sing_plural(num, sing, plur):
    if num <= 1:
        return '%d %s' % (num, sing)
    else:
        return '%d %s' % (num, plur)

def display_string(s):
    if len(s) == 0:
        return "''"
    else:
        return s

def set_union(set_list):
    new_set = set([])
    for s in set_list:
        if s is not None:
            new_set = new_set.union(s)

    return new_set

def print_usage():
    print('\nUsage: python ' + sys.argv[0] + ' [-a] [-x <sect>] <input_file>')
    print('\nOption:')
    print('   -a  Report about all user accounts, including locked, ' + \
          'Oracle-supplied users\n')
    print('   -x  Specify sections to exclude from report ' + \
          '(may be repeated for multiple sections)')

sections = (
#    {'id': None, 'name': 'Basic Information',
    {'id': None, 'name': '基本情報'.decode('utf-8'),
        'funcs': (sec_feature_usage, patch_checks)
    },
#    {'id': 'USER', 'name': 'User Accounts',
    {'id': 'USER', 'name': 'ユーザーアカウント'.decode('utf-8'),
        'funcs': (user_section,)
    },
#    {'id': 'PRIV', 'name': 'Privileges and Roles',
    {'id': 'PRIV', 'name': '権限とロール'.decode('utf-8'),
        'funcs': (privs_and_roles, java_permission)
    },
#    {'id': 'AUTH', 'name': 'Authorization Control',
    {'id': 'AUTH', 'name': '権限付与のコントロール'.decode('utf-8'),
        'funcs': (database_vault, privilege_capture)
    },
#    {'id': 'ACCESS', 'name': 'Fine-Grained Access Control',
    {'id': 'ACCESS', 'name': 'ファイングレインアクセス制御'.decode('utf-8'),
        'funcs': (redaction, vpd_policy, ras_policy, label_security,
            tsdp_policy)
    },
#    {'id': 'AUDIT', 'name': 'Auditing',
    {'id': 'AUDIT', 'name': '監査'.decode('utf-8'),
        'funcs': (audit_trail, unified_audit_policy, check_audited_connect_stmt, 
              check_admin_audit, check_audited_system_stmt, 
              check_audited_account_stmt, privilege_audit, role_audit,
              check_audited_privs_usage, check_audited_grant_stmt,
              statement_audit, object_audit, fine_grained_audit)
                 
    },
#    {'id': 'CRYPT', 'name': 'Encryption',
    {'id': 'CRYPT', 'name': '暗号化'.decode('utf-8'),
        'funcs': (data_encryption, encryption_wallet)
    },
#    {'id': 'CONF', 'name': 'Database Configuration',
    {'id': 'CONF', 'name': 'データベース構成'.decode('utf-8'),
        'funcs': (security_parameters, sec_parameter_checks, trace_files,
            instance_name_check, triggers, disabled_constraint, external_procedure, 
            directories_info, dblink_info, network_acl, xml_acl, rman_bkup)
    },
#    {'id': 'NET', 'name': 'Network Configuration',
    {'id': 'NET', 'name': 'ネットワーク構成'.decode('utf-8'),
        'funcs': (sqlnet_ora, listener_ora)
    },
#    {'id': 'OS', 'name': 'Operating System',
    {'id': 'OS', 'name': 'オペレーティングシステム'.decode('utf-8'),
        'funcs': (os_authentication_user, pmon_agent_tnslsnr,
            db_file_permission)
    }
)
all_sections = [s['id'] for s in sections if s['id'] is not None]

if __name__ == '__main__':
    excluded_sections = set()
    show_all_grants = False
    try:
        opts, argv = getopt.getopt(sys.argv[1:], 'adgx:',
            ['all-accounts', 'exclude=', 'diagnostics'])
    except Exception as e:
        print(e)
        print_usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-a', '--all-accounts'):
            check_oracle_accts = True
        elif opt in ('-g', '--all-grants'):
            show_all_grants = True
        elif opt in ('-d', '--diagnostics'):
            sat.enablediag()
        elif opt in ('-x', '--exclude'):
            for sect in arg.upper().split(','):
                if sect in all_sections:
                    excluded_sections.add(sect)
                else:
                    print('Unrecognized section: ' + sect)
                    print('Valid sections are: ' + join_list(all_sections))
                    sys.exit(1)
    if len(argv) < 1:
        print_usage()
        sys.exit(1)

    node = argv[0]

    try:
        sat.read_json(node)
    except Exception as e:
        print('Unable to process input file: ' + node+'.json')
        print(e)
        sys.exit(1)

    ver_data = sat.get_data('END',1)
    if ver_data is not None:
       if ver_data[0][0] != VERSION:
          print('Warning: The input file was generated ' + \
                'by a different version of DBSAT collector.')

    sat.start_report(node)

    populate_globals() 
    enumerate_users()

    db_identification(sys.argv[0])

    for sect in sections:
        if sect['id'] not in excluded_sections:
            sat.start_section(sect['name'])
            for fn in sect['funcs']:
                try:
                    fn()
                except Exception as e:
                    sat.diag('Unexpected error in ' + fn.__name__)
                    print(traceback.format_exc())
            sat.end_section()

    sat.end_report()
