#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2015-2016 VMware, Inc. All Rights Reserved.
#
# Licensed under the X11 (MIT) (the “License”) set forth below;
#
# you may not use this file except in compliance with the License. Unless required by applicable law or agreed to in
# writing, software distributed under the License is distributed on an “AS IS” BASIS, without warranties or conditions
# of any kind, EITHER EXPRESS OR IMPLIED. See the License for the specific language governing permissions and
# limitations under the License. Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# "THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.”

import argparse
import ConfigParser
from argparse import RawTextHelpFormatter
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from pkg_resources import resource_filename
from libutils import dfw_rule_list_helper, connect_to_vc, nametovalue, get_edge, check_edge_id, check_logical_switch_id
from libutils import check_network, get_logical_switch

__author__ = 'Dimitri Desmidt, Emanuele Mazza, Yves Fauser'


def get_dfw_section(client_session, section_name):
    """
    :param client_session: An instance of an NsxClient Session
    :param section_name: DFW Section Name
    :return: The first item being the dfw section id as string,
                the second item beeing (session_name, session_id, session_type)
    """
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    try:
        section_params = [val for session in sections for val in session if val[0] == section_name][0]
        section_id = section_params[1]
    except IndexError:
        return None, None
    return section_id, section_params

def get_dfw_section_type(client_session, section_id):
    """
    :param client_session: An instance of an NsxClient Session
    :param section_id: DFW Section ID
    :return: The first item being the dfw section type (LAYER2, LAYER3, L3REDIRECT),
                the second item beeing (session_name, session_id, session_type)
    """
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    try:
        section_params = [val for session in sections for val in session if val[1] == section_id][0]
        section_type = section_params[2]
    except IndexError:
        return None, None
    return section_type, section_params



def dfw_section_list(client_session):
    """
    This function returns all the sections of the NSX distributed firewall
    :param client_session: An instance of an NsxClient Session
    :return returns
            - for each of the three available sections types (L2, L3Redirect, L3) a list with item 0 containing the
              section name as string, item 1 containing the section id as string, item 2 containing the section type
              as a string
            - a dictionary containing all sections' details, including dfw rules
    """
    all_dfw_sections = client_session.read('dfwConfig')['body']['firewallConfiguration']

    if str(all_dfw_sections['layer2Sections']) != 'None':
        l2_dfw_sections = all_dfw_sections['layer2Sections']['section']
    else:
        l2_dfw_sections = list()

    if str(all_dfw_sections['layer2Sections']) != 'None':
        l3r_dfw_sections = all_dfw_sections['layer3RedirectSections']['section']
    else:
        l3r_dfw_sections = list()

    if str(all_dfw_sections['layer3Sections']) != 'None':
        l3_dfw_sections = all_dfw_sections['layer3Sections']['section']
    else:
        l3_dfw_sections = list()

    l2_section_list = [['---', '---', '---']]
    l3r_section_list = [['---', '---', '---']]
    l3_section_list = [['---', '---', '---']]

    if type(l2_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l2_dfw_sections), dict.values(l2_dfw_sections))
        l2_dfw_sections = list()
        l2_dfw_sections.append(dict(keys_and_values))

    if type(l3_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3_dfw_sections), dict.values(l3_dfw_sections))
        l3_dfw_sections = list()
        l3_dfw_sections.append(dict(keys_and_values))

    if type(l3r_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3r_dfw_sections), dict.values(l3r_dfw_sections))
        l3r_dfw_sections = list()
        l3r_dfw_sections.append(dict(keys_and_values))

    if len(l2_dfw_sections) != 0:
        l2_section_list = list()
        for sl in l2_dfw_sections:
            try:
                section_name = sl['@name']
            except KeyError:
                section_name = '<empty name>'
            l2_section_list.append((section_name, sl['@id'], sl['@type']))

    if len(l3r_dfw_sections) != 0:
        l3r_section_list = list()
        for sl in l3r_dfw_sections:
            try:
                section_name = sl['@name']
            except KeyError:
                section_name = '<empty name>'
            l3r_section_list.append((section_name, sl['@id'], sl['@type']))

    if len(l3_dfw_sections) != 0:
        l3_section_list = list()
        for sl in l3_dfw_sections:
            try:
                section_name = sl['@name']
            except KeyError:
                section_name = '<empty name>'
            l3_section_list.append((section_name, sl['@id'], sl['@type']))

    return l2_section_list, l3r_section_list, l3_section_list, all_dfw_sections


def _dfw_section_list_print(client_session, **kwargs):
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    if kwargs['verbose']:
        print detailed_dfw_sections
    else:
        print tabulate(l2_section_list, headers=["Name", "ID", "Type"], tablefmt="psql")
        print tabulate(l3r_section_list, headers=["Name", "ID", "Type"], tablefmt="psql")
        print tabulate(l3_section_list, headers=["Name", "ID", "Type"], tablefmt="psql")


def dfw_section_delete(client_session, section_id):
    """
    This function delete a section given its id
    :param client_session: An instance of an NsxClient Session
    :param section_id: The id of the section that must be deleted
    :return returns
            - A table containing these information: Return Code (True/False), Section ID, Section Name, Section Type
            - ( verbose option ) A list containing a single list which elements are Return Code (True/False),
              Section ID, Section Name, Section Type

            If there is no matching list
                - Return Code is set to False
                - Section ID is set to the value passed as input parameter
                - Section Name is set to "---"
                - Section Type is set to "---"
    """
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)

    dfw_section_id = str(section_id)

    for i, val in enumerate(l3_section_list):
        if dfw_section_id == str(val[1]) and str(val[0]) != 'Default Section Layer3':
            client_session.delete('dfwL3SectionId', uri_parameters={'sectionId': dfw_section_id})
            #result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            #return result
            code = "True"
            name = str(val[0])
            type = str(val[-1])
            return dfw_section_id, name, type, code
        if dfw_section_id == str(val[1]) and str(val[0]) == 'Default Section Layer3':
            # result = [["False-Delete Default Section is not allowed", dfw_section_id, "---", "---"]]
            # return result
            code = "False"
            name = "Default Section Layer3"
            type = "LAYER3"
            return dfw_section_id, name, type, code

    for i, val in enumerate(l2_section_list):
        if dfw_section_id == str(val[1]) and str(val[0]) != 'Default Section Layer2':
            client_session.delete('dfwL2SectionId', uri_parameters={'sectionId': dfw_section_id})
            # result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            # return result
            code = "True"
            name = str(val[0])
            type = str(val[-1])
            return dfw_section_id, name, type, code
        if dfw_section_id == str(val[1]) and str(val[0]) == 'Default Section Layer2':
            # result = [["False-Delete Default Section is not allowed", dfw_section_id, "---", "---"]]
            # return result
            code = "False"
            name = "Default Section Layer2"
            type = "LAYER2"
            return dfw_section_id, name, type, code

    for i, val in enumerate(l3r_section_list):
        if dfw_section_id == str(val[1]) and str(val[0]) != 'Default Section':
            client_session.delete('section', uri_parameters={'section': dfw_section_id})
            # result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            # return result
            code = "True"
            name = str(val[0])
            type = str(val[-1])
            return dfw_section_id, name, type, code
        if dfw_section_id == str(val[1]) and str(val[0]) == 'Default Section':
            # result = [["False-Delete Default Section is not allowed", dfw_section_id, "---", "---"]]
            # return result
            code = "False"
            name = "Default Section"
            type = "L3REDIRECT"
            return dfw_section_id, name, type, code

    # result = [["False", dfw_section_id, "---", "---"]]
    # return result
    code = "False"
    name = str(val[0])
    type = str(val[-1])
    return dfw_section_id, name, type, code

def _dfw_section_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    section_id = kwargs['dfw_section_id']
    # result = dfw_section_delete(client_session, section_id)
    id, name, type, code = dfw_section_delete(client_session, section_id)

    if code == "True":
        print 'Section {} with ID {} of type {} has been deleted'.format(name,id,type)
    elif code == "False":
        print 'Section {} with ID {} of type {} has not been deleted'.format(name,id,type)

    # if kwargs['verbose']:
        # print result
    # else:
        # print tabulate(result, headers=["Return Code", "Section ID", "Section Name", "Section Type"], tablefmt="psql")


def dfw_rule_delete(client_session, rule_id):
    """
    This function delete a dfw rule given its id
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The id of the rule that must be deleted
    :return returns
            - A table containing these information: Return Code (True/False), Rule ID, Rule Name, Applied-To, Section ID
            - ( verbose option ) A list containing a single list which elements are Return Code (True/False),
              Rule ID, Rule Name, Applied-To, Section ID

            If there is no matching rule
                - Return Code is set to False
                - Rule ID is set to the value passed as input parameter
                - All other returned parameters are set to "---"
    """
    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)
    dfw_rule_id = str(rule_id)

    for i, val in enumerate(l3_rule_list):
        if dfw_rule_id == str(val[0]) and str(val[1]) != 'Default Rule':
            dfw_section_id = str(val[-1])
            section_list, dfwL3_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('dfwL3Rule', uri_parameters={'ruleId': dfw_rule_id, 'sectionId': dfw_section_id},
                                  additional_headers={'If-match': etag})
            # result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            # return result
            code = "True"
            id = dfw_rule_id
            name = str(val[1])
            section = str(val[-1])
            return id, name, section, code
        else:
            # result = [["False-Delete Default Rule is not allowed", dfw_rule_id, "---", "---", "---"]]
            # return result
            code = "False"
            id = dfw_rule_id
            name = "Default Rule L3"
            section = ""
            # return id, name, section, code

    for i, val in enumerate(l2_rule_list):
        if dfw_rule_id == str(val[0]) and str(val[1]) != 'Default Rule':
            dfw_section_id = str(val[-1])
            section_list, dfwL2_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('dfwL2Rule', uri_parameters={'ruleId': dfw_rule_id, 'sectionId': dfw_section_id},
                                  additional_headers={'If-match': etag})
            # result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            # return result
            code = "True"
            id = dfw_rule_id
            name = str(val[1])
            section = str(val[-1])
            return id, name, section, code
        else:
            # result = [["False-Delete Default Rule is not allowed", dfw_rule_id, "---", "---", "---"]]
            # return result
            code = "False"
            id = dfw_rule_id
            name = "Default Rule L2"
            section = ""
            # return id, name, section, code

    for i, val in enumerate(l3r_rule_list):
        if dfw_rule_id == str(val[0]) and str(val[1]) != 'Default Rule':
            dfw_section_id = str(val[-1])
            section_list, dfwL3r_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('rule', uri_parameters={'ruleID': dfw_rule_id, 'section': dfw_section_id})
            # result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            # return result
            code = "True"
            id = dfw_rule_id
            name = str(val[1])
            section = str(val[-1])
            return id, name, section, code
        else:
            # result = [["False-Delete Default Rule is not allowed", dfw_rule_id, "---", "---", "---"]]
            # return result
            code = "False"
            id = dfw_rule_id
            name = "Default Rule L3REDIRECT"
            section = ""
            return id, name, section, code

    # result = [["False", dfw_rule_id, "---", "---", "---"]]
    # return result
    # code = "False"
    # id = dfw_rule_id
    # name = ""
    # section = ""
    return id, name, section, code


def _dfw_rule_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    rule_id = kwargs['dfw_rule_id']
    # result = dfw_rule_delete(client_session, rule_id)
    id, name, section, code = dfw_rule_delete(client_session, rule_id)

    if code == "True":
        print 'Rule {} with ID {} applied to section with id {} has been deleted'.format(name,id,section)
    elif code == "False":
        print 'Rule {} with ID {} has not been deleted'.format(name,id)

    # if kwargs['verbose']:
        # print result
    # else:
        # print tabulate(result, headers=["Return Code", "Rule ID", "Rule Name", "Applied-To", "Section ID"],
                       # tablefmt="psql")


def dfw_section_id_read(client_session, dfw_section_name):
    """
    This function returns the section(s) ID(s) given a section name
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_name: The name ( case sensitive ) of the section for which the ID is wanted
    :return returns
            - A list of dictionaries. Each dictionary contains the type and the id of each section with named as
              specified by the input parameter. If no such section exist, the list contain a single dictionary with
              {'Type': 0, 'Id': 0}
    """
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    dfw_section_id = list()
    dfw_section_name = str(dfw_section_name)

    for i, val in enumerate(l3_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    for i, val in enumerate(l3r_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    for i, val in enumerate(l2_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    if len(dfw_section_id) == 0:
        dfw_section_id.append({'Type': 0, 'Id': 0})
    return dfw_section_id


def _dfw_section_id_read_print(client_session, **kwargs):

    if not (kwargs['dfw_section_name']):
        print ('Mandatory parameters missing: [-sname SECTION NAME]')
        return None
    dfw_section_name = str(kwargs['dfw_section_name'])
    dfw_section_id = dfw_section_id_read(client_session, dfw_section_name)

    if kwargs['verbose']:
        print dfw_section_id
    else:
        dfw_section_id_csv = ",".join([str(section['Id']) for section in dfw_section_id])
        print dfw_section_id_csv

def dfw_rule_id_read(client_session, dfw_section_id, dfw_rule_name):
    """
    This function returns the rule(s) ID(s) given a section id and a rule name
    :param client_session: An instance of an NsxClient Session
    :param dfw_rule_name: The name ( case sensitive ) of the rule for which the ID is/are wanted. If rhe name includes
                      includes spaces, enclose it between ""
    :param dfw_section_id: The id of the section where the rule must be searched
    :return returns
            - A dictionary with the rule name as the key and a list as a value. The list contains all the matching
              rules id(s). For example {'RULE_ONE': [1013, 1012]}. If no matching rule exist, an empty dictionary is
              returned
    """

    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)

    list_names = list()
    list_ids = list()
    dfw_rule_name = str(dfw_rule_name)
    dfw_section_id = str(dfw_section_id)

    for i, val in enumerate(l2_rule_list):
        if (dfw_rule_name == val[1]) and (dfw_section_id == val[-1]):
            list_names.append(dfw_rule_name)
            list_ids.append(int(val[0]))

    for i, val in enumerate(l3_rule_list):
        if (dfw_rule_name == val[1]) and (dfw_section_id == val[-1]):
            list_names.append(dfw_rule_name)
            list_ids.append(int(val[0]))

    for i, val in enumerate(l3r_rule_list):
        if (dfw_rule_name == val[1]) and (dfw_section_id == val[-1]):
            list_names.append(dfw_rule_name)
            list_ids.append(int(val[0]))

    dfw_rule_id = dict.fromkeys(list_names, list_ids)
    return dfw_rule_id


def _dfw_rule_id_read_print(client_session, **kwargs):

    if not (kwargs['dfw_rule_name']):
        print ('Mandatory parameters missing: [-rname RULE NAME (use "" if name includes spaces)]')
        return None
    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    dfw_section_id = str(kwargs['dfw_section_id'])
    dfw_rule_name = str(kwargs['dfw_rule_name'])

    dfw_rule_id = dfw_rule_id_read(client_session, dfw_section_id, dfw_rule_name)

    if kwargs['verbose']:
        print dfw_rule_id
    else:
        try:
            dfw_rule_ids_str = [str(ruleid) for ruleid in dfw_rule_id[dfw_rule_name]]
            dfw_rule_id_csv = ",".join(dfw_rule_ids_str)
            print tabulate([(dfw_rule_name, dfw_rule_id_csv)], headers=["Rule Name", "Rule IDs"], tablefmt="psql")
        except KeyError:
            print 'Rule name {} not found in section Id {}'.format(kwargs['dfw_rule_name'], kwargs['dfw_section_id'])


def dfw_rule_list(client_session):
    """
    This function returns all the rules of the NSX distributed firewall
    :param client_session: An instance of an NsxClient Session
    :return returns
            - a tabular view of all the  dfw rules defined across L2, L3, L3Redirect
            - ( verbose option ) a list containing as many list as the number of dfw rules defined across
              L2, L3, L3Redirect (in this order). For each rule, these fields are returned:
              "ID", "Name", "Source", "Destination", "Service", "Action", "Direction", "Packet Type", "Applied-To",
              "ID (Section)"
    """
    all_dfw_sections_response = client_session.read('dfwConfig')
    all_dfw_sections = client_session.normalize_list_return(all_dfw_sections_response['body']['firewallConfiguration'])

    if str(all_dfw_sections[0]['layer3Sections']) != 'None':
        l3_dfw_sections = all_dfw_sections[0]['layer3Sections']['section']
    else:
        l3_dfw_sections = list()

    if str(all_dfw_sections[0]['layer2Sections']) != 'None':
        l2_dfw_sections = all_dfw_sections[0]['layer2Sections']['section']
    else:
        l2_dfw_sections = list()

    if str(all_dfw_sections[0]['layer3RedirectSections']) != 'None':
        l3r_dfw_sections = all_dfw_sections[0]['layer3RedirectSections']['section']
    else:
        l3r_dfw_sections = list()

    if type(l2_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l2_dfw_sections), dict.values(l2_dfw_sections))
        l2_dfw_sections = list()
        l2_dfw_sections.append(dict(keys_and_values))

    if type(l3_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3_dfw_sections), dict.values(l3_dfw_sections))
        l3_dfw_sections = list()
        l3_dfw_sections.append(dict(keys_and_values))

    if type(l3r_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3r_dfw_sections), dict.values(l3r_dfw_sections))
        l3r_dfw_sections = list()
        l3r_dfw_sections.append(dict(keys_and_values))

    l2_temp = list()
    l2_rule_list = list()
    if len(l2_dfw_sections) != 0:
        for i, val in enumerate(l2_dfw_sections):
            if 'rule' in val:
                l2_temp.append(l2_dfw_sections[i])
        l2_dfw_sections = l2_temp
        if len(l2_dfw_sections) > 0:
            if 'rule' in l2_dfw_sections[0]:
                rule_list = list()
                for sptr in l2_dfw_sections:
                    section_rules = client_session.normalize_list_return(sptr['rule'])
                    l2_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
        else:
            l2_rule_list = []

    l3_temp = list()
    l3_rule_list = list()
    if len(l3_dfw_sections) != 0:
        for i, val in enumerate(l3_dfw_sections):
            if 'rule' in val:
                l3_temp.append(l3_dfw_sections[i])
        l3_dfw_sections = l3_temp
        if len(l3_dfw_sections) > 0:
            if 'rule' in l3_dfw_sections[0]:
                rule_list = list()
                for sptr in l3_dfw_sections:
                    section_rules = client_session.normalize_list_return(sptr['rule'])
                    l3_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
        else:
            l3_rule_list = []

    l3r_temp = list()
    l3r_rule_list = list()
    if len(l3r_dfw_sections) != 0:
        for i, val in enumerate(l3r_dfw_sections):
            if 'rule' in val:
                l3r_temp.append(l3r_dfw_sections[i])
        l3r_dfw_sections = l3r_temp
        if len(l3r_dfw_sections) > 0:
            if 'rule' in l3r_dfw_sections[0]:
                rule_list = list()
                for sptr in l3r_dfw_sections:
                    section_rules = client_session.normalize_list_return(sptr['rule'])
                    l3r_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
        else:
            l3r_rule_list = []

    return l2_rule_list, l3_rule_list, l3r_rule_list


def _dfw_rule_list_print(client_session, **kwargs):
    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)
    if kwargs['verbose']:
        print l2_rule_list, l3_rule_list, l3r_rule_list
    else:
        print ''
        print '*** ETHERNET RULES ***'
        print tabulate(l2_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")
        print ''
        print '*** LAYER 3 RULES ***'
        print tabulate(l3_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")

        print''
        print '*** REDIRECT RULES ***'
        print tabulate(l3r_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                               "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_read(client_session, rule_id):
    """
    This function retrieves details of a dfw rule given its id
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :return: returns
            - tabular view of the dfw rule
            - ( verbose option ) a list containing the dfw rule information: ID(Rule)- Name(Rule)- Source- Destination-
              Services- Action - Direction- Pktytpe- AppliedTo- ID(section)
    """
    rule_list = dfw_rule_list(client_session)
    rule = list()

    for sectionptr in rule_list:
        for ruleptr in sectionptr:
            if ruleptr[0] == str(rule_id):
                rule.append(ruleptr)
    return rule


def _dfw_rule_read_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    rule_id = kwargs['dfw_rule_id']
    rule = dfw_rule_read(client_session, rule_id)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_source_delete(client_session, rule_id, source):
    """
    This function delete one of the sources of a dfw rule given the rule id and the source to be deleted
    If two or more sources have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param source: The source of the dfw rule to be deleted. If the source name contains any space, then it must be
                   enclosed in double quotes (like "VM Network")
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule informations after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    source = str(source)
    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", source, "---", "---", "---", "---", "---", "---", "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if 'sources' not in rule_schema.items()[1][1]['rule']:
        # It means the only source is "any" and it cannot be deleted short of deleting the whole rule
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['sources']['source']) == list:
        # It means there are more than one sources, each one with his own dict
        sources_list = rule_schema.items()[1][1]['rule']['sources']['source']
        for i, val in enumerate(sources_list):
            if val['type'] == 'Ipv4Address' and val['value'] == source or 'name' in val and val['name'] == source:
                del rule_schema.items()[1][1]['rule']['sources']['source'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['sources']['source']) == dict:
        # It means there is just one explicit source with his dict
        source_dict = rule_schema.items()[1][1]['rule']['sources']['source']
        if source_dict['type'] == 'Ipv4Address' and source_dict['value'] == source or \
                                  'name' in dict.keys(source_dict) and source_dict['name'] == source:
            del rule_schema.items()[1][1]['rule']['sources']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_source_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_source']):
        print ('Mandatory parameters missing: [-src RULE SOURCE]')
        return None
    rule_id = kwargs['dfw_rule_id']
    source = kwargs['dfw_rule_source']
    rule = dfw_rule_source_delete(client_session, rule_id, source)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_destination_delete(client_session, rule_id, destination):
    """
    This function delete one of the destinations of a dfw rule given the rule id and the destination to be deleted.
    If two or more destinations have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param destination: The destination of the dfw rule to be deleted. If the destination name contains any space, then
                        it must be enclosed in double quotes (like "VM Network")
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule informations after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    destination = str(destination)
    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", "---", destination, "---", "---", "---", "---", "---", "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if 'destinations' not in rule_schema.items()[1][1]['rule']:
        # It means the only destination is "any" and it cannot be deleted short of deleting the whole rule
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['destinations']['destination']) == list:
        # It means there are more than one destinations, each one with his own dict
        destination_list = rule_schema.items()[1][1]['rule']['destinations']['destination']
        for i, val in enumerate(destination_list):
            if val['type'] == 'Ipv4Address' and val['value'] == destination or \
                                    'name' in val and val['name'] == destination:
                del rule_schema.items()[1][1]['rule']['destinations']['destination'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['destinations']['destination']) == dict:
        # It means there is just one explicit destination with his dict
        destination_dict = rule_schema.items()[1][1]['rule']['destinations']['destination']
        if destination_dict['type'] == 'Ipv4Address' and destination_dict['value'] == destination or \
                                       'name' in dict.keys(destination_dict) and \
                                       destination_dict['name'] == destination:
            del rule_schema.items()[1][1]['rule']['destinations']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_destination_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_destination']):
        print ('Mandatory parameters missing: [-dst RULE DESTINATION]')
        return None
    rule_id = kwargs['dfw_rule_id']
    destination = kwargs['dfw_rule_destination']
    rule = dfw_rule_destination_delete(client_session, rule_id, destination)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")

def dfw_rule_create(client_session, vccontent,
                    section_id=None, section_name=None,
                    rule_name=None,
                    rule_source_value=None, rule_source_name=None, rule_source_type=None,
                    rule_source_excluded=None,
                    rule_destination_value=None, rule_destination_name=None, rule_destination_type=None,
                    rule_destination_excluded=None,
                    rule_service_name=None,
                    rule_service_protocolname=None, rule_service_destport=None, rule_service_srcport=None,
                    rule_direction=None, rule_pktype=None,
                    rule_applyto_type=None, rule_applyto_id=None, rule_applyto_name=None,
                    rule_disabled=None, rule_action=None,
                    rule_logged=None, rule_note=None, rule_tag=None):

    """
    This function will create a new rule in NSX DFW
    The mandatory parameters are: client_session, [section_id|section_name].

    :param client_session: An instance of an NsxClient Session
    :param rule_name: The new DFW rule name (default: empty)
    :param section_id: The DFW section id
    :param section_name: The DFW section name
    :param rule_source_type: DFW Destination Type (default = Ipv4Address) (list of values below)
    :param rule_source_value: DFW rule Source.
                                If rule_source_type = Ipv4Address, enter "any" or "IP/subnet".
                                If rule_source_type != Ipv4Address and rule_source_name empty, enter Object Id
                                (default = "any") (List of supported options: VirtualWire, Ipv4Address)
    :param rule_source_name: If rule_source_type != Ipv4Address, enter Object name (default = empty)
    :param rule_source_excluded: To deny the DFW rule Source (default: "false")
    :param rule_destination_type: DFW Destination Type (default = Ipv4Address) (list of values below)
    :param rule_destination_value: DFW rule Destination.
                                If rule_destination_type = Ipv4Address, enter "any" or "IP/subnet".
                                If rule_destination_type != Ipv4Address and rule_destination_name empty, enter Object Id
                                (default = "any")
    :param rule_destination_name: If rule_destination_type != Ipv4Address, enter Object name (default = empty)
    :param rule_destination_excluded: To deny the DFW rule Destination (default: "false")
    :param rule_service_name: DFW rule Server Name (default: empty = any)
                                (list of option = look at the NSX Service. ie: HTTP, SSH)
    :param rule_service_protocolname: DFW rule Service Protocol Name. If empty rule_service_name used
                                (default: empty = Not used) (list of option = look at the NSX Protocols. ie: TCP, UDP)
    :param rule_service_destport: DFW rule Service Destination Port. Only used if rule_service_protocolname not empty.
    :param rule_service_srcport: DFW rule Service Source Port. Only used if rule_service_protocolname not empty.
    :param rule_direction: DFW Direction (default: inout)
    :param rule_pktype: DFW PacketType (default: any)
    :param rule_applyto_type: DFW Apply To Type (default = DISTRIBUTED_FIREWALL)
                                (List of supported options: Edge, VirtualWire(LS), DISTRIBUTED_FIREWALL)
    :param rule_applyto_name: When rule_applyto_type != than dfw, enter object name
                                (default = empty) (optional between rule_applyto_id and rule_applyto_name)
    :param rule_applyto_id: When rule_applyto_type != than dfw and rule_applyto_id empty, specify Object ID \
                                (default = empty) (optional between rule_applyto_id and rule_applyto_name)
    :param rule_disabled: DFW rule disabled (default: false)
    :param rule_action: DFW rule action (default: allow) (list of options: reject, deny)
    :param rule_logged: DFW rule logging (default: false)
    :param rule_note: DFW rule note (default: empty)
    :param rule_tag: DFW rule tag (default: empty)


    :return: returns a tuple, the first item is the rule ID in NSX as string, the second is string
             containing the dlr URL location as returned from the API
    """

    # Set defaults value if empty
    if not rule_source_value:
        rule_source_value='any'
    if not rule_source_type:
        rule_source_type='Ipv4Address'
    if not rule_source_excluded:
        rule_source_excluded='false'
    if not rule_destination_value:
        rule_destination_value='any'
    if not rule_destination_type:
        rule_destination_type='Ipv4Address'
    if not rule_destination_excluded:
        rule_destination_excluded='false'
    if not rule_direction:
        rule_direction='inout'
    if not rule_pktype:
        rule_pktype='any'
    if not rule_applyto_type:
        rule_applyto_type='DISTRIBUTED_FIREWALL'
    if not rule_disabled:
        rule_disabled='false'
    if not rule_action:
        rule_action='allow'
    if not rule_logged:
        rule_logged='false'

    # Convert section_name if used
    if section_name:
        section_id, section_params = get_dfw_section(client_session, section_name)
        if not section_id:
            print 'ERROR: section_name {} does NOT exist in DFW'.format(section_name)
            return None

    # Validate section_id is a L3 DFW section: LAYER3
    section_type, section_params = get_dfw_section_type(client_session, section_id)
    if not section_type:
        print 'ERROR: section_id {} does NOT exist in DFW'.format(section_id)
        return None
    if not section_type == 'LAYER3':
        print 'ERROR: section_id {} is NOT a LAYER3 section'.format(section_id)
        return None

    # Get the DFW etag number
    read_section = client_session.read('dfwL3SectionId', uri_parameters={'sectionId': section_id})
    read_section_etag = read_section.items()[-1][1]

    # get a template dict for the DFW Layer3 rule
    rule_L3_schema = client_session.extract_resource_body_example('dfwL3Rules', 'create')


    # rule_action
    # Since NSX UI shows rule_action "block", people may enter "block" where the API wants "deny"
    if rule_action == 'block':
        rule_action = 'deny'
    if not (rule_action in ('allow', 'reject', 'deny')):
        print 'ERROR: rule_action {} MUST be  allow, reject, or deny'.format(rule_action)
        return None
    else:
        rule_L3_schema['rule']['action'] = rule_action

    # rule_applyto
    if not (rule_applyto_type in ('Edge', 'VirtualWire', 'DISTRIBUTED_FIREWALL')):
        print 'ERROR: rule_applyto_type {} MUST be Edge, VirtualWire, or DISTRIBUTED_FIREWALL'.format(rule_applyto_type)
        return None

    rule_L3_schema['rule']['appliedToList']['appliedTo']['type'] = rule_applyto_type
    if rule_applyto_type == 'DISTRIBUTED_FIREWALL':
        rule_L3_schema['rule']['appliedToList']['appliedTo']['value'] = 'DISTRIBUTED_FIREWALL'

    elif ((not rule_applyto_name) and (not rule_applyto_id)):
        print 'ERROR: rule_applyto_type = {} and requires at least rule_applyto_name ' \
              'or rule_applyto_id'.format(rule_applyto_type)
        return None
    elif rule_applyto_type == 'Edge':
        if rule_applyto_name:
            rule_applyto_id, edge_params = get_edge(client_session, rule_applyto_name)
            if not rule_applyto_id:
                print 'ERROR: Edge_Name {} does NOT exist in Edge list'.format(rule_applyto_name)
                return None
            rule_L3_schema['rule']['appliedToList']['appliedTo']['value'] = rule_applyto_id
        elif rule_applyto_id:
            if check_edge_id(client_session, rule_applyto_id):
                rule_L3_schema['rule']['appliedToList']['appliedTo']['value'] = rule_applyto_id
            else:
                print 'ERROR: rule_applyto_id {} MUST be existing Edge id'.format(rule_applyto_id)
                return None

    elif rule_applyto_type == 'VirtualWire':
        if rule_applyto_name:
            rule_applyto_id, ls_params = get_logical_switch(client_session, rule_applyto_name)
            if not rule_applyto_id:
                print 'ERROR: rule_applyto_name {} does NOT exist in LS list'.format(rule_applyto_name)
                return None
            rule_L3_schema['rule']['appliedToList']['appliedTo']['value'] = rule_applyto_id
        elif rule_applyto_id:
            if check_logical_switch_id(client_session, rule_applyto_id):
                rule_L3_schema['rule']['appliedToList']['appliedTo']['value'] = rule_applyto_id
            else:
                print 'ERROR: rule_applyto_id {} MUST be existing Logical Switch ID. ' \
                      'If Logical Switch name use rule_applyto_name'.format(rule_applyto_id)
                return None

    # rule_source
    if not (rule_source_type in ('VirtualWire', 'Ipv4Address')):
        print 'ERROR: rule_source_type {} MUST be currently VirtualWire, or Ipv4Address'.format(rule_applyto_type)
        return None

    if not (rule_source_excluded in ('false', 'true')):
        print 'ERROR: rule_source_excluded {} MUST be false, or true'.format(rule_source_excluded)
        return None
    rule_L3_schema['rule']['sources']['@excluded'] = rule_source_excluded
    rule_L3_schema['rule']['sources']['source']['isValid'] = 'true'

    rule_L3_schema['rule']['sources']['source']['type'] = rule_source_type
    del rule_L3_schema['rule']['sources']['source']['name']
    if rule_source_type == 'Ipv4Address':
        if rule_source_value == 'any' or not rule_source_value :
            del rule_L3_schema['rule']['sources']
        elif check_network (client_session, rule_source_value):
            rule_L3_schema['rule']['sources']['source']['value'] = rule_source_value
        else:
            print 'ERROR: rule_source_type = Ipv4Address, ' \
                  'and rule_source_value {} MUST be a subnet x.x.x.x/y'.format(rule_source_value)
            return None

    elif rule_source_type == 'VirtualWire':
        if rule_source_name:
            rule_source_value, ls_params = get_logical_switch(client_session, rule_source_name)
            if not rule_source_value:
                print 'ERROR: rule_source_name {} does NOT exist in LS list'.format(rule_source_name)
                return None
            rule_L3_schema['rule']['sources']['source']['value'] = rule_source_value
        else:
            if check_logical_switch_id(client_session, rule_source_value):
                rule_L3_schema['rule']['sources']['source']['value'] = rule_source_value
            else:
                print 'ERROR: rule_source_value {} MUST be existing Logical Switch ID. ' \
                      'If Logical Switch name use rule_applyto_name'.format(rule_source_value)
                return None

    # rule_destination
    if not (rule_destination_type in ('VirtualWire', 'Ipv4Address')):
        print 'ERROR: rule_destination_type {} MUST be currently VirtualWire, or Ipv4Address'.format(rule_applyto_type)
        return None

    if not (rule_destination_excluded in ('false', 'true')):
        print 'ERROR: rule_destination_excluded {} MUST be false, or true'.format(rule_destination_excluded)
        return None
    rule_L3_schema['rule']['destinations']['@excluded'] = rule_destination_excluded
    rule_L3_schema['rule']['destinations']['destination']['isValid'] = 'true'

    rule_L3_schema['rule']['destinations']['destination']['type'] = rule_destination_type
    del rule_L3_schema['rule']['destinations']['destination']['name']
    if rule_destination_type == 'Ipv4Address':
        if rule_destination_value == 'any' or not rule_destination_value :
            del rule_L3_schema['rule']['destinations']
        elif check_network (client_session, rule_destination_value):
            rule_L3_schema['rule']['destinations']['destination']['value'] = rule_destination_value
        else:
            print 'ERROR: rule_destination_type = Ipv4Address, ' \
                  'and rule_destination_value {} MUST be a subnet x.x.x.x/y'.format(rule_destination_value)
            return None

    elif rule_destination_type == 'VirtualWire':
        if rule_destination_name:
            rule_destination_value, ls_params = get_logical_switch(client_session, rule_destination_name)
            if not rule_destination_value:
                print 'ERROR: rule_destination_name {} does NOT exist in LS list'.format(rule_destination_name)
                return None
            rule_L3_schema['rule']['destinations']['destination']['value'] = rule_destination_value
        else :
            if check_logical_switch_id(client_session, rule_destination_value):
                rule_L3_schema['rule']['destinations']['destination']['value'] = rule_destination_value
            else:
                print 'ERROR: rule_destination_value {} MUST be existing Logical Switch ID.' \
                      'if Logical Switch name use rule_applyto_name'.format(rule_destination_value)
                return None

    # rule_service
    # If "rule_service_name = any" or "nothing specified" => any service
    if (rule_service_name == 'any' ) or ((not rule_service_name) and (not rule_service_protocolname)):
        del rule_L3_schema['rule']['services']
    # If rule_service_name specified
    if rule_service_name:
        # Check Service exists in NSX service list
        services = client_session.read('servicesScope', uri_parameters={'scopeId': 'globalroot-0'})
        service = services.items()[1][1]['list']['application']
        list_services = ()
        for servicedict in service:
            list_services = list_services + (servicedict['name'],)
        if not (rule_service_name in list_services):
            print 'ERROR: list_services {} MUST be defined in NSX service list'.format(rule_service_name)
            return None
        rule_service_id = [servicedict for servicedict in service \
                           if servicedict['name'] == rule_service_name][0]['objectId']
        rule_L3_schema['rule']['services']['service']['value'] = rule_service_id
        rule_L3_schema['rule']['services']['service']['type'] = "Application"
    elif rule_service_protocolname:
        # xxx To Do validate rule_service_protocolname is a valid protocol
        del rule_L3_schema['rule']['services']['service']['value']
        rule_L3_schema['rule']['services']['service']['protocolName'] = rule_service_protocolname
        if rule_service_destport:
            # xxx To Do validate rule_service_destport is a valid port / port_list
            rule_L3_schema['rule']['services']['service']['destinationPort'] = rule_service_destport
        if rule_service_srcport:
            # xxx To Do validate rule_service_srcport is a valid port / port_list
            rule_L3_schema['rule']['services']['service']['sourcePort'] = rule_service_srcport


    # others
    rule_L3_schema['rule']['name'] = rule_name
    rule_L3_schema['rule']['direction'] = rule_direction
    rule_L3_schema['rule']['packetType'] = rule_pktype
    rule_L3_schema['rule']['@disabled'] = rule_disabled
    rule_L3_schema['rule']['notes'] = rule_note
    rule_L3_schema['rule']['tag'] = rule_tag
    rule_L3_schema['rule']['@logged'] = rule_logged

    new_rule = client_session.create('dfwL3Rules', uri_parameters={'sectionId': section_id},
                                     request_body_dict=rule_L3_schema,
                                     additional_headers={'If-match': read_section_etag})
    return new_rule['objectId'], new_rule['location']



def _dfw_rule_create(client_session, vccontent, **kwargs):
    if not ((kwargs['dfw_section_id']) or (kwargs['dfw_section_name'])):
        print ('Mandatory parameters missing: [-sid SECTION ID] or [-sname SECTION Name]')
        return None
    section_id = kwargs['dfw_section_id']
    section_name = kwargs['dfw_section_name']

    rule_name = kwargs['dfw_rule_name']
    rule_source_value = kwargs['dfw_rule_source_value']
    rule_source_name = kwargs['dfw_rule_source_name']
    rule_source_type = kwargs['dfw_rule_source_type']
    rule_source_excluded = kwargs['dfw_rule_source_excluded']
    rule_destination_value = kwargs['dfw_rule_destination_value']
    rule_destination_name = kwargs['dfw_rule_destination_name']
    rule_destination_type = kwargs['dfw_rule_destination_type']
    rule_destination_excluded = kwargs['dfw_rule_destination_excluded']
    rule_service_name = kwargs['dfw_rule_service_name']
    rule_service_protocolname = kwargs['dfw_rule_service_protocolname']
    rule_service_destport = kwargs['dfw_rule_service_destport']
    rule_service_srcport = kwargs['dfw_rule_service_srcport']
    rule_direction = kwargs['dfw_rule_direction']
    rule_pktype = kwargs['dfw_rule_pktype']
    rule_applyto_type = kwargs['dfw_rule_applyto_type']
    rule_applyto_id = kwargs['dfw_rule_applyto_id']
    rule_applyto_name = kwargs['dfw_rule_applyto_name']
    rule_disabled = kwargs['dfw_rule_disabled']
    rule_action = kwargs['dfw_rule_action']
    rule_logged = kwargs['dfw_rule_logged']
    rule_note = kwargs['dfw_rule_note']
    rule_tag = kwargs['dfw_rule_tag']


    dfw_rule_id, dfw_rule_params = dfw_rule_create(client_session, vccontent,
                    section_id, section_name,
                    rule_name,
                    rule_source_value, rule_source_name, rule_source_type,
                    rule_source_excluded,
                    rule_destination_value, rule_destination_name, rule_destination_type,
                    rule_destination_excluded,
                    rule_service_name,
                    rule_service_protocolname, rule_service_destport, rule_service_srcport,
                    rule_direction, rule_pktype,
                    rule_applyto_type, rule_applyto_id, rule_applyto_name,
                    rule_disabled, rule_action,
                    rule_logged, rule_note, rule_tag)

    '''
    dfw_rule_id, dfw_rule_params = dfw_rule_create(client_session, vccontent,
                    section_id=section_id, section_name=section_name,
                    rule_name=rule_name,
                    rule_source_value=rule_source_value, rule_source_name=rule_source_name,
                                                   rule_source_type=rule_source_type,
                    rule_source_excluded=rule_source_excluded,
                    rule_destination_value=rule_destination_value, rule_destination_name=rule_destination_name,
                                                   rule_destination_type=rule_destination_type,
                    rule_destination_excluded=rule_destination_excluded,
                    rule_service_name=rule_service_name,
                    rule_service_protocolname=rule_service_protocolname, rule_service_destport=rule_service_destport,
                                                   rule_service_srcport=rule_service_srcport,
                    rule_direction=rule_direction, rule_pktype=rule_pktype,
                    rule_applyto_type=rule_applyto_type, rule_applyto_id=rule_applyto_id,
                                                   rule_applyto_name=rule_applyto_name,
                    rule_disabled=rule_disabled, rule_action=rule_action,
                    rule_logged=rule_logged, rule_note=rule_note, rule_tag=rule_tag)
    '''

    if kwargs['verbose']:
        print dfw_rule_params
    else:
        print 'DFW rule created with the ID {}'.format(dfw_rule_id)


def dfw_rule_service_delete(client_session, rule_id, service):
    """
    This function delete one of the services of a dfw rule given the rule id and the service to be deleted.
    If two or more services have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param service: The service of the dfw rule to be deleted. If the service name contains any space, then
                    it must be enclosed in double quotes (like "VM Network"). For TCP/UDP services the syntax is as
                    follows: Proto:SourcePort:DestinationPort ( example TCP:9090:any )
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule informations after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    service = str(service).split(':', 3)
    if len(service) == 1:
        service.append('')
    if len(service) == 2:
        service.append('')

    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", "---", "---", service, "---", "---", "---", "---", "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if 'services' not in rule_schema.items()[1][1]['rule']:
        # It means the only service is "any" and it cannot be deleted short of deleting the whole rule
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['services']['service']) == list:
        # It means there are more than one services, each one with his own dict
        service_list = rule_schema.items()[1][1]['rule']['services']['service']
        for i, val in enumerate(service_list):
            if ('name' in val and val['name'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
            and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val and
            val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
            and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val
            and val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
            and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val
            and val['protocolName'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
            and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val and
            val['protocolName'] == service[0]):
                del rule_schema.items()[1][1]['rule']['services']['service'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['services']['service']) == dict:
        # It means there is just one explicit service with his dict
        service_dict = rule_schema.items()[1][1]['rule']['services']['service']
        val = service_dict

        if ('name' in val and val['name'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
        and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val and
        val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
        and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val
        and val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
        and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val
        and val['protocolName'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
        and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val and
        val['protocolName'] == service[0]):
            del rule_schema.items()[1][1]['rule']['services']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_service_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_service']):
        print ('Mandatory parameters missing: [-srv RULE SERVICE]')
        return None
    rule_id = kwargs['dfw_rule_id']
    service = kwargs['dfw_rule_service']
    rule = dfw_rule_service_delete(client_session, rule_id, service)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_applyto_delete(client_session, rule_id, applyto):
    """
    This function delete one of the applyto clauses of a dfw rule given the rule id and the clause to be deleted.
    If two or more clauses have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param applyto: The name of the applyto clause of the dfw rule to be deleted. If it contains any space, then
                    it must be enclosed in double quotes (like "VM Network").
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule information after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    apply_to = str(applyto)
    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", "---", "---", "---", "---", "---", "---", apply_to, "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if type(rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']) == list:
        # It means there are more than one applyto clauses, each one with his own dict
        applyto_list = rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']
        for i, val in enumerate(applyto_list):
            if 'name' in val and val['name'] == apply_to:
                del rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']) == dict:
        # It means there is just one explicit applyto clause with his dict
        applyto_dict = rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']
        val = applyto_dict

        if 'name' in val and val['name'] == "DISTRIBUTED_FIREWALL":
            # It means the only applyto clause is "DISTRIBUTED_FIREWALL" and it cannot be deleted short of deleting
            # the whole rule
            rule = dfw_rule_read(client_session, rule_id)
            return rule

        if 'name' in val and val['name'] == apply_to:
            del rule_schema.items()[1][1]['rule']['appliedToList']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_applyto_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_applyto_id']):
        print ('Mandatory parameters missing: [-appto RULE APPLYTO]')
        return None
    rule_id = kwargs['dfw_rule_id']
    applyto = kwargs['dfw_rule_applyto_id']
    rule = dfw_rule_applyto_delete(client_session, rule_id, applyto)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_section_read(client_session, dfw_section_id):
    """
    This function retrieves details of a dfw section given its id
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_id: The ID of the dfw section to retrieve details from
    :return: returns
            - a tabular view of the section with the following information: Name, Section id, Section type, Etag
            - ( verbose option ) a dictionary containing all sections's details
    """
    section_list = []
    dfw_section_id = str(dfw_section_id)
    uri_parameters = {'sectionId': dfw_section_id}

    dfwL3_section_details = dict(client_session.read('dfwL3SectionId', uri_parameters))

    section_name = dfwL3_section_details['body']['section']['@name']
    section_id = dfwL3_section_details['body']['section']['@id']
    section_type = dfwL3_section_details['body']['section']['@type']
    section_etag = dfwL3_section_details['Etag']
    section_list.append((section_name, section_id, section_type, section_etag))

    return section_list, dfwL3_section_details


def _dfw_section_read_print(client_session, **kwargs):
    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    dfw_section_id = kwargs['dfw_section_id']
    section_list, dfwL3_section_details = dfw_section_read(client_session, dfw_section_id)

    if kwargs['verbose']:
        print dfwL3_section_details['body']
    else:
        print tabulate(section_list, headers=["Name", "ID", "Type", "Etag"], tablefmt="psql")


def dfw_section_create(client_session, dfw_section_name, dfw_section_type):
    """
    This function creates a new dfw section given its name and its type
    The new section is created on top of all other existing sections and with no rules
    If a section of the same time and with the same name already exist, nothing is done
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_name: The name of the dfw section to be created
    :param dfw_section_type: The type of the section. Allowed values are L2/L3/L3R
    :return: returns
            - a tabular view of all the sections of the same type of the one just created. The table contains the
              following information: Name, Section id, Section type
            - ( verbose option ) a dictionary containing for each possible type all sections' details, including
              dfw rules
    """

    dfw_section_name = str(dfw_section_name)
    dfw_section_selector = str(dfw_section_type)

    if dfw_section_selector != 'L2' and dfw_section_selector != 'L3' and dfw_section_selector != 'L3R':
        print ('Section Type Unknown - Allowed values are L2/L3/L3R -- Aborting')
        return

    if dfw_section_selector == 'L2':
        dfw_section_type = 'dfwL2Section'

    elif dfw_section_selector == 'L3':
        dfw_section_type = 'dfwL3Section'

    else:
        dfw_section_type = 'layer3RedirectSections'

    # Regardless of the final rule type this line below is the correct way to get the empty schema
    section_schema = client_session.extract_resource_body_example('dfwL3Section', 'create')
    section_schema['section']['@name'] = dfw_section_name

    # Delete the rule section to create an empty section
    del section_schema['section']['rule']

    # Check for duplicate sections of the same type as the one that will be created, create and return
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)

    if dfw_section_type == 'dfwL2Section':
        for val in l2_section_list:
            if dfw_section_name in val:
                # Section with the same name already exist
                return l2_section_list, detailed_dfw_sections
        section = client_session.create(dfw_section_type, request_body_dict=section_schema)
        return section['body']['section']['@id'], section['location'], section['Etag'], \
            section['body']['section']['@name']
        #l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
        #return l2_section_list, detailed_dfw_sections

    if dfw_section_type == 'dfwL3Section':
        for val in l3_section_list:
            if dfw_section_name in val:
                # Section with the same name already exist
                return l3_section_list, detailed_dfw_sections
        section = client_session.create(dfw_section_type, request_body_dict=section_schema)
        # l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
        # return l3_section_list, detailed_dfw_sections
        return section['body']['section']['@id'], section['location'], section['Etag'], \
            section['body']['section']['@name']

    if dfw_section_type == 'layer3RedirectSections':
        for val in l3r_section_list:
            if dfw_section_name in val:
                # Section with the same name already exist
                return l3r_section_list, detailed_dfw_sections
        section = client_session.create(dfw_section_type, request_body_dict=section_schema)
        return section['body']['section']['@id'], section['location'], section['Etag'], \
            section['body']['section']['@name']
        #l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
        #return l3r_section_list, detailed_dfw_sections


def _dfw_section_create_print(client_session, **kwargs):
    if not (kwargs['dfw_section_name']):
        print ('Mandatory parameters missing: [-sname SECTION NAME]')
        return None

    if not (kwargs['dfw_section_type']):
        print ('Mandatory parameters missing: [-stype SECTION TYPE] - Allowed values are L2/L3/L3R -- Aborting')
        return None

    if kwargs['dfw_section_type'] != 'L3' and kwargs['dfw_section_type'] != 'L2' and kwargs['dfw_section_type'] != 'L3R':
        print ('Incorrect parameter: [-stype SECTION TYPE] - Allowed values are L2/L3/L3R -- Aborting')
        return None

    dfw_section_name = kwargs['dfw_section_name']
    dfw_section_type = kwargs['dfw_section_type']

    # section_list, detailed_dfw_sections = dfw_section_create(client_session, dfw_section_name, dfw_section_type)
    id, location, Etag, name = dfw_section_create(client_session, dfw_section_name, dfw_section_type)

    if kwargs['verbose']:
        print 'Section {} created with ID {} Etag {} and location {}'.format(name, id, Etag, location)
    else:
        print 'Section {} created with ID {}'.format(name, id)

    #if kwargs['verbose']:
        #print detailed_dfw_sections
    #else:
        #print tabulate(section_list, headers=["Name", "ID", "Type"], tablefmt="psql")


def contruct_parser(subparsers):
    parser = subparsers.add_parser('dfw', description="Functions for distributed firewall",
                                   help="Functions for distributed firewall",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    list_sections:   return a list of all distributed firewall's sections
    read_section:    return the details of a dfw section given its id
    read_section_id: return the id of a section given its name (case sensitive)
    create_section:  create a new section given its name and its type (L2,L3,L3R)
    delete_section:  delete a section given its id
    list_rules:      return a list of all distributed firewall's rules
    read_rule:       return the details of a dfw rule given its id
    read_rule_id:    return the id of a rule given its name and the id of the section to which it belongs
    create_rule:     create a new rule given the id of the section, the rule name and all the rule parameters
    delete_rule:     delete a rule given its id
    delete_rule_source: delete one rule's source given the rule id and the source identifier
    delete_rule_destination: delete one rule's destination given the rule id and the destination identifier
    delete_rule_service: delete one rule's service given the rule id and the service identifier
    delete_rule_applyto: delete one rule's applyto clause given the rule id and the applyto clause identifier
    move_rule_above:   move one rule above another rule given the id of the rule to be moved and the id of the base rule
    """)

    parser.add_argument("-sid",
                        "--dfw_section_id",
                        help="dfw section id needed for create, read and delete operations")
    parser.add_argument("-sname",
                        "--dfw_section_name",
                        help="dfw section name")
    parser.add_argument("-rid",
                        "--dfw_rule_id",
                        help="dfw rule id needed for create, read and delete operations")
    parser.add_argument("-rname",
                        "--dfw_rule_name",
                        help="dfw rule name")
    parser.add_argument("-dir",
                        "--dfw_rule_direction",
                        help="dfw rule direction")
    parser.add_argument("-pktype",
                        "--dfw_rule_pktype",
                        help="dfw rule packet type")
    parser.add_argument("-disabled",
                        "--dfw_rule_disabled",
                        help="dfw rule disabled")
    parser.add_argument("-action",
                        "--dfw_rule_action",
                        help="dfw rule action")
    parser.add_argument("-src",
                        "--dfw_rule_source",
                        help="dfw rule source")
    parser.add_argument("-srctype",
                        "--dfw_rule_source_type",
                        help="dfw rule source type")
    parser.add_argument("-srcname",
                        "--dfw_rule_source_name",
                        help="dfw rule source name")
    parser.add_argument("-srcvalue",
                        "--dfw_rule_source_value",
                        help="dfw rule source value")
    parser.add_argument("-srcexcluded",
                        "--dfw_rule_source_excluded",
                        help="dfw rule source excluded")
    parser.add_argument("-dst",
                        "--dfw_rule_destination",
                        help="dfw rule destination")
    parser.add_argument("-dsttype",
                        "--dfw_rule_destination_type",
                        help="dfw rule destination type")
    parser.add_argument("-dstname",
                        "--dfw_rule_destination_name",
                        help="dfw rule destination name")
    parser.add_argument("-dstvalue",
                        "--dfw_rule_destination_value",
                        help="dfw rule destination value")
    parser.add_argument("-dstexcluded",
                        "--dfw_rule_destination_excluded",
                        help="dfw rule destination excluded")
    parser.add_argument("-srv",
                        "--dfw_rule_service",
                        help="dfw rule service")
    parser.add_argument("-srvprotoname",
                        "--dfw_rule_service_protocolname",
                        help="dfw rule service protocol name")
    parser.add_argument("-srvdestport",
                        "--dfw_rule_service_destport",
                        help="dfw rule service destination port")
    parser.add_argument("-srvsrcport",
                        "--dfw_rule_service_srcport",
                        help="dfw rule service source port")
    parser.add_argument("-srvname",
                        "--dfw_rule_service_name",
                        help="dfw rule service name")
    parser.add_argument("-apptoid",
                        "--dfw_rule_applyto_id",
                        help="dfw rule applyto id")
    parser.add_argument("-apptoname",
                        "--dfw_rule_applyto_name",
                        help="dfw rule applyto name")
    parser.add_argument("-apptotype",
                        "--dfw_rule_applyto_type",
                        help="dfw rule applyto type")
    parser.add_argument("-note",
                        "--dfw_rule_note",
                        help="dfw rule note")
    parser.add_argument("-tag",
                        "--dfw_rule_tag",
                        help="dfw rule tag")
    parser.add_argument("-logged",
                        "--dfw_rule_logged",
                        help="dfw rule logged")
    parser.add_argument("-brid",
                        "--dfw_rule_base_id",
                        help="dfw rule base id")
    parser.add_argument("-stype",
                        "--dfw_section_type",
                        help="dfw section type")

    parser.set_defaults(func=_dfw_main)


def _dfw_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    try:
        nsxramlfile = config.get('nsxraml', 'nsxraml_file')
    except (ConfigParser.NoSectionError):
        nsxramlfile_dir = resource_filename(__name__, 'api_spec')
        nsxramlfile = '{}/nsxvapi.raml'.format(nsxramlfile_dir)

    client_session = NsxClient(nsxramlfile, config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    vccontent = connect_to_vc(config.get('vcenter', 'vcenter'), config.get('vcenter', 'vcenter_user'),
                              config.get('vcenter', 'vcenter_passwd'))

    try:
        command_selector = {
            'list_sections': _dfw_section_list_print,
            'read_section': _dfw_section_read_print,
            'list_rules': _dfw_rule_list_print,
            'read_rule': _dfw_rule_read_print,
            'read_section_id': _dfw_section_id_read_print,
            'read_rule_id': _dfw_rule_id_read_print,
            'delete_section': _dfw_section_delete_print,
            'delete_rule': _dfw_rule_delete_print,
            'delete_rule_source': _dfw_rule_source_delete_print,
            'delete_rule_destination': _dfw_rule_destination_delete_print,
            'delete_rule_service': _dfw_rule_service_delete_print,
            'delete_rule_applyto': _dfw_rule_applyto_delete_print,
            'create_section': _dfw_section_create_print,
            'create_rule': _dfw_rule_create,
            }
        command_selector[args.command](client_session, vccontent=vccontent, verbose=args.verbose,
                                       dfw_section_id=args.dfw_section_id, dfw_section_name=args.dfw_section_name,
                                       dfw_rule_id=args.dfw_rule_id,
                                       dfw_rule_name=args.dfw_rule_name, dfw_rule_source=args.dfw_rule_source,
                                       dfw_rule_destination=args.dfw_rule_destination,
                                       dfw_rule_service=args.dfw_rule_service,
                                       dfw_rule_applyto_id=args.dfw_rule_applyto_id,
                                       dfw_rule_applyto_name=args.dfw_rule_applyto_name,
                                       dfw_rule_applyto_type=args.dfw_rule_applyto_type,
                                       dfw_rule_base_id=args.dfw_rule_base_id, dfw_section_type=args.dfw_section_type,
                                       dfw_rule_direction=args.dfw_rule_direction, dfw_rule_pktype=args.dfw_rule_pktype,
                                       dfw_rule_disabled=args.dfw_rule_disabled, dfw_rule_action=args.dfw_rule_action,
                                       dfw_rule_source_type=args.dfw_rule_source_type,
                                       dfw_rule_source_name=args.dfw_rule_source_name,
                                       dfw_rule_source_value=args.dfw_rule_source_value,
                                       dfw_rule_source_excluded=args.dfw_rule_source_excluded,
                                       dfw_rule_destination_type=args.dfw_rule_destination_type,
                                       dfw_rule_destination_name=args.dfw_rule_destination_name,
                                       dfw_rule_destination_value=args.dfw_rule_destination_value,
                                       dfw_rule_destination_excluded=args.dfw_rule_destination_excluded,
                                       dfw_rule_service_protocolname=args.dfw_rule_service_protocolname,
                                       dfw_rule_service_destport=args.dfw_rule_service_destport,
                                       dfw_rule_service_srcport=args.dfw_rule_service_srcport,
                                       dfw_rule_service_name=args.dfw_rule_service_name,
                                       dfw_rule_tag=args.dfw_rule_tag, dfw_rule_note=args.dfw_rule_note,
                                       dfw_rule_logged=args.dfw_rule_logged)

    except KeyError as e:
        print('Unknown command {}'.format(e))


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
