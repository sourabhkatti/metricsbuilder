import os
import base64
import json
import requests
import argparse
import datetime


class applicationgrouper:
    ORGANIZATION_ID = "142bb017-de7e-4af7-b5b9-f0782aa6d369"
    TEAMSERVER_URL = "https://app.contrastsecurity.com/Contrast/api/ng/"
    API_KEY = "vgy5soZn15wnVPHH539pF8F7niofbl4N"
    SERVICE_KEY = "4K5V00T6JB90KPAD"
    USERNAME = "danielan@us.ibm.com"
    outputpath = os.getcwd()

    def __init__(self):
        self.AUTHORIZATION = base64.b64encode((self.USERNAME + ':' + self.SERVICE_KEY).encode('utf-8'))

    def sortapplications(self):

        application_names = []

        try:
            filereader = open(self.outputpath + "/applications.txt", 'r')
            for line in filereader:
                application_names.append(line)
        except:
            endpoint = self.ORGANIZATION_ID + "/applications"
            url = self.TEAMSERVER_URL + endpoint

            header = {
                "API-Key": self.API_KEY,
                "Authorization": self.AUTHORIZATION,
            }

            # Get response
            response = requests.get(url=url, headers=header, stream=True)
            jsonreader = json.loads(response.text)

            # Setup file to output results to
            filename = self.outputpath + "/applications.txt"
            filewriter = open(filename, 'w+')

            # Loop through each application
            if jsonreader["success"] is True:
                applications = jsonreader["applications"]
                for application in applications:
                    application_names.append(application['name'])
                    filewriter.write((application['name'] + "\n"))
            filewriter.close()

        print("%d applications loaded!" % application_names.__len__())
        self.groupapplications(application_names)

    def groupapplications(self, application_names):
        applications_groups = {}
        for app_name in application_names:
            applications_groups[app_name] = []

        for application_name in application_names:
            CHAR_RANGE = int(0.5 * application_name.__len__())
            CHAR_END = application_name.__len__()
            for application_key in applications_groups.keys():
                for i in range(0, CHAR_END - CHAR_RANGE):
                    char_subset = application_name[i: i + CHAR_RANGE]
                    if application_key.find(char_subset) and application_key != application_name:
                        applications_groups[application_key] += [application_name]
                    else:
                        continue
                    i += 1
        print("done")

    def getgroups(self):
        group_names = []
        endpoint = self.ORGANIZATION_ID + "/groups"
        url = self.TEAMSERVER_URL + endpoint

        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        # Get response
        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        # Setup file to output results to
        filename = self.outputpath + "/applications.txt"
        filewriter = open(filename, 'w+')

        # Loop through each application
        if jsonreader["success"] is True:
            custom_groups = jsonreader["custom_groups"]
            for custom_group in custom_groups['groups']:
                group_names.append(custom_group['group_id'])
                filewriter.write((str(custom_group['group_id']) + "\n"))
                custom_groups = jsonreader["custom_groups"]

            predefined_groups = jsonreader["predefined_groups"]
            for default_group in predefined_groups['groups']:
                group_names.append(default_group['group_id'])
                filewriter.write((str(default_group['group_id']) + "\n"))
        filewriter.close()

        print(group_names.__len__())
        print("Groups done")
        self.getapplications(group_names)

    def getapplications(self, group_ids):
        endpoint = self.ORGANIZATION_ID + "/groups/"
        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        spreadsheet = []

        for group_id in group_ids:
            spreadsheetrow = ''
            url = self.TEAMSERVER_URL + endpoint + str(group_id)

            # Get response
            response = requests.get(url=url, headers=header, stream=True)
            jsonreader = json.loads(response.text)

            # Setup file to output results to
            filename = self.outputpath + "/applications.txt"
            filewriter = open(filename, 'w+')

            # Loop through each application
            if jsonreader["success"] is True:
                currentgroup = jsonreader['group']
                spreadsheetrow += currentgroup['name'] + ','
                print(currentgroup['name'])
                try:
                    if currentgroup['applications'].__len__() > 0:
                        applications = currentgroup['applications'][0]['applications']
                        for application in applications:
                            print('\t' + application['name'])
                            spreadsheetrow += application['name'] + ','
                except:
                    continue
                spreadsheet.append('\n' + spreadsheetrow)

            i = 0
        self.filewriter(spreadsheet)

    def filewriter(self, spreadsheet):
        filename = self.outputpath + "/groups.csv"
        filewriter = open(filename, 'w+')

        for row in spreadsheet:
            filewriter.write(row)
        filewriter.close()


applicationgrouper = applicationgrouper()
applicationgrouper.getgroups()
