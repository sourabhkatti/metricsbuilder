import sys
import base64
import json
import requests
import csv

from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.colors import Color
from reportlab.lib.pagesizes import A4, inch, portrait
from reportlab.lib.units import inch
from reportlab.rl_config import defaultPageSize
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak, Spacer
from reportlab.platypus.tables import CellStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


class data:
    ORGANIZATION_ID = "887de447-fc8c-4295-90f9-6442e3890d27"
    TEAMSERVER_URL = "http://localhost:8081/Contrast/api/ng/"
    API_KEY = "C3e2Ygy8qPzsEqU4"
    SERVICE_KEY = "LSG784SHM209JAMQ"
    USERNAME = "sweetrabh@gmail.com"

    # ORGANIZATION_ID = "0f767995-4882-4c7c-889f-994d945ff0d5"
    # TEAMSERVER_URL = "https://apptwo.contrastsecurity.com/Contrast/api/ng/"
    # API_KEY = "B6Y14MfSBsmLC6k4GxhIlGk297ZuvG9N"
    # SERVICE_KEY = "ZO2XIX3CU9AOCKDM"
    # USERNAME = "michelle.chen@contrastsecurity.com"

    def __init__(self):
        self.AUTHORIZATION = base64.b64encode((self.USERNAME + ':' + self.SERVICE_KEY).encode('utf-8'))

    def createDictionary(self):
        endpoint = self.ORGANIZATION_ID + "/applications"
        url = self.TEAMSERVER_URL + endpoint
        header = {"API-Key": self.API_KEY, "Authorization": self.AUTHORIZATION}
        response = requests.get(url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        # Creating a list of app_ids to hold in all app_id values
        app_id_list = []
        for item in xrange(len(jsonreader['applications'])):
            app_id_list.append(jsonreader['applications'][item]['app_id'])
        # Creating a dictionary of app_ids with key app_id
        app_id_dict = {}
        for item in app_id_list:
            app_id_dict[item] = {}

        # Loop through app_id_list for trace, CRITICALS, HIGHS, MEDS, LOWS, NOTES
        # /ng/{orgUuid}/applications/{appId}/breakdown/trace
        # https://apptwo.contrastsecurity.com/Contrast/api/ng/0f767995-4882-4c7c-889f-994d945ff0d5/applications/9cb8f5c7-ffed-4def-af5c-34f946d28654?expand=scores,trace_breakdown

        master_app_list = []  # Contains master app ids
        child_app_list = []  # Contains child app ids
        master_app = []  # Contains master app names
        child_app = []  # Contains child app names
        unlicensed_app_list = []  # Contains unlicensed app ids

        for item in app_id_list:
            url = self.TEAMSERVER_URL + self.ORGANIZATION_ID + "/applications/" + item + "?expand=scores,license,trace_breakdown"
            response = requests.get(url, headers=header, stream=True)
            jsonreader = json.loads(response.text)
            app_id_dict[item] = {'name': jsonreader['application']['name'],
                                 'score': jsonreader['application']['scores']['letter_grade'],
                                 'criticals': jsonreader['application']['trace_breakdown']['criticals'],
                                 'highs': str(jsonreader['application']['trace_breakdown']['highs']),
                                 'meds': str(jsonreader['application']['trace_breakdown']['meds']),
                                 'lows': str(jsonreader['application']['trace_breakdown']['lows']),
                                 'notes': jsonreader['application']['trace_breakdown']['notes']}
            app_id_dict[item]['childApp'] = []

            # Search for applications which are not licensed
            if jsonreader['application']['license']['level'] == "Unlicensed":
                item2 = jsonreader['application']
                unlicensed_app_list.append(item2['app_id'])

            # Search for master apps via master=true setting and save app id
            if jsonreader['application']['master'] is True:
                item = jsonreader['application']['app_id']
                url = self.TEAMSERVER_URL + self.ORGANIZATION_ID + "/modules/" + item + "?expand=trace_breakdown"
                response = requests.get(url, headers=header, stream=True)
                jsonreader = json.loads(response.text)

                # Create child dictionary containing name and trace: CRITICALS, HIGHS, MEDS, LOWS, NOTES
                for item2 in jsonreader['applications']:
                    child_dict = {}
                    child_dict['name'] = item2['name']
                    child_dict['app_id'] = item2['app_id']
                    child_dict['trace_breakdown'] = {'criticals': item2['trace_breakdown']['criticals'],
                                                     'highs': item2['trace_breakdown']['highs'],
                                                     'meds': item2['trace_breakdown']['meds'],
                                                     'lows': item2['trace_breakdown']['lows'],
                                                     'notes': item2['trace_breakdown']['notes']}
                    app_id_dict[item]['childApp'].append(child_dict)
                    child_app_list.append(item2['app_id'])

                    # Remove child id's from list of keys
        for item in child_app_list:
            del app_id_dict[item]

        # Remove unlicensed app id's from list of keys
        for item in unlicensed_app_list:
            del app_id_dict[item]

        return app_id_dict

        # Send the data and build the file
        elements.append(t)
        doc.build(elements)
        return data3

    def generatePDF(self):
        app_id_dict = self.createDictionary()
        doc = SimpleDocTemplate("test_report_lab94.pdf", pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30,
                                bottomMargin=18)
        doc.pagesize = portrait(A4)
        elements = []

        # initialize background colors
        backgroundRed = ParagraphStyle(name='background-red', backColor=colors.red, spaceAfter=6, spaceBefore=6)
        backgroundOrange = ParagraphStyle(name='background-orange', backColor=colors.orange, spaceAfter=6,
                                          spaceBefore=6)
        backgroundGreen = ParagraphStyle(name='background-green', backColor=colors.green, spaceAfter=6, spaceBefore=6)

        # populate data
        data = [["Application", "Grade", "High", "Med", "Low"]]
        for item in app_id_dict:
            data.append([app_id_dict[item]['name'], app_id_dict[item]['score'], app_id_dict[item]['highs'],
                         app_id_dict[item]['meds'], app_id_dict[item]['lows']])

        # print(data)
        # print (json.dumps(app_id_dict, indent=4, sort_keys=True))

        # elements.append(PageBreak())
        style = TableStyle([  # ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            # ('LEFTPADDING', (1, 1), (-4, -1), 0),
            # ('RIGHTPADDING', (1, 1), (-4, -1), 0),
            # ('TOPPADDING', (1,1), (-4,-1), 0),
            # ('BOTTOMPADDING', (1,1), (-4,-1), 0),
        ])
        # style = TableStyle([('ALIGN',(1,1),(-2,-2),'RIGHT'),
        #                            ('TEXTCOLOR',(1,1),(-2,-2),colors.red),
        #                            ('VALIGN',(0,0),(0,-1),'TOP'),
        #                            ('TEXTCOLOR',(0,0),(0,-1),colors.blue),
        #                            ('ALIGN',(0,-1),(-1,-1),'CENTER'),
        #                            ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
        #                            ('HALIGN',(0,-1),(-1,-1),'CENTER'),
        #                            ('TEXTCOLOR',(0,-1),(-1,-1),colors.green),
        #                            ('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),
        #                            ('BOX', (0,0), (-1,-1), 0.25, colors.black),
        #                            ])


        # Configure style and word wrap
        s = getSampleStyleSheet()
        s = s["BodyText"]
        s.wordWrap = 'CJK'
        data2 = []

        for i, row in enumerate(data):
            rows = []
            if i == 0:
                s.fontName = 'Helvetica-Bold'
            else:
                s.fontName = 'Helvetica'
            for cell in row:
                # if cell == 'D' or cell == 'F':
                #     rows.append(Paragraph(cell,backgroundRed))
                # elif cell == 'C':
                #     rows.append(Paragraph(cell,backgroundOrange))
                # elif cell == 'A' or cell == 'B':
                #     rows.append(Paragraph(cell,backgroundGreen))
                # else:
                rows.append(Paragraph(cell, s))

                # for i, row in enumerate(data):
                #     rows = []
                #     if i == 0:
                #         s.fontName = 'Helvetica-Bold'
                #     else:
                #         s.fontName = 'Helvetica'
                #     for cell in row:
                #         if cell == 'D' or cell == 'F':
                #             rows.append(CellStyle(cell))
                #         elif cell == 'C':
                #             rows.append(CellStyle(cell))
                #         elif cell == 'A' or cell == 'B':
                #             rows.append(CellStyle(cell))
                #         else:
                #             rows.append(ParagraphStyle(cell,s))
            data2.append(rows)

        t = Table(data2)
        t.setStyle(style)
        # Send the data and build the file
        elements.append(t)
        elements.append(PageBreak())

        # if child app exists, add parent and child to data list
        for item in app_id_dict.values():
            try:
                childapps = item['childApp']
                if len(childapps) > 0:
                    data3 = []
                    # check to see if there are any case where vuln = 0
                    if item['highs'] == '0':
                        if item['meds'] == '0':
                            if item['lows'] == '0':  # if high/med/low = 0
                                continue
                            else:  # if high/med = 0
                                data3.append([item['name'], item['score'], "Low" + ':' + '\t' + item['lows']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "Low"])
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['lows'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('VALIGN',(0,0),(0,-1),'TOP'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('INNERGRID', (3, 0), (4, 1), 0.25, colors.white),  # removing grid for first row
                                    ('INNERGRID', (3, 2), (4, -1), 0.25, colors.white),
                                    # removing grid for rest of high/med
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),  # removing box for grade
                                    ('BOX', (2, 0), (2, 0), 0.25, colors.black),
                                    ('BOX', (3, 2), (-1, -1), 0.25, colors.white),  # removing box for rest of high/med
                                    ('BOX', (0, 2), (-3, -1), 0.25, colors.black),
                                ])
                        else:  # if high = 0 and med != 0
                            if item['lows'] == '0':  # check if high/low = 0
                                data3.append([item['name'], item['score'], "Med" + ':' + '\t' + item['meds']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "Med"])
                                # data3.append(self.getMergedHeader())
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['meds'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('VALIGN',(0,0),(0,-1),'TOP'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('INNERGRID', (3, 0), (4, 1), 0.25, colors.white),  # removing grid for first row
                                    ('INNERGRID', (3, 2), (4, -1), 0.25, colors.white),
                                    # removing grid for rest of high/low
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),
                                    ('BOX', (2, 0), (2, 0), 0.25, colors.black),
                                    ('BOX', (3, 2), (-1, -1), 0.25, colors.white),  # removing box for rest of high/low
                                    ('BOX', (0, 2), (-3, -1), 0.25, colors.black),
                                ])
                            else:  # if high=0, med!=0, low !=0
                                data3.append([item['name'], item['score'], "Med" + ':' + '\t' + item['meds'],
                                              "Low" + ':' + '\t' + item['lows']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "Med", "Low"])
                                # data3.append(self.getMergedHeader())
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['meds']),
                                                  str(childapp['trace_breakdown']['lows'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('VALIGN',(0,0),(0,-1),'TOP'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('INNERGRID', (4, 0), (4, 1), 0.25, colors.white),  # removing grid for first row
                                    ('INNERGRID', (4, 2), (4, -1), 0.25, colors.white),
                                    # removing grid for rest of high
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),
                                    ('BOX', (2, 0), (3, 0), 0.25, colors.black),
                                    ('BOX', (4, 2), (-1, -1), 0.25, colors.white),  # removing box for rest of high
                                    ('BOX', (0, 2), (-2, -1), 0.25, colors.black),
                                ])
                    else:  # if high != 0, then check if med = 0
                        if item['meds'] == '0':  # if med = 0, check if low = 0
                            if item['lows'] == '0':  # if med/low = 0
                                data3.append([item['name'], item['score'], "High" + ':' + '\t' + item['highs']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "High"])
                                # data3.append(self.getMergedHeader())
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['highs'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('VALIGN',(0,0),(0,-1),'TOP'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('INNERGRID', (3, 0), (4, 1), 0.25, colors.white),  # removing grid for first row
                                    ('INNERGRID', (3, 2), (4, -1), 0.25, colors.white),
                                    # removing grid for rest of med/low
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),
                                    ('BOX', (2, 0), (2, 0), 0.25, colors.black),
                                    ('BOX', (3, 2), (-1, -1), 0.25, colors.white),  # removing box for rest of med/low
                                    ('BOX', (0, 2), (-3, -1), 0.25, colors.black),
                                ])
                            else:  # if just med = 0
                                data3.append([item['name'], item['score'], "High" + ':' + '\t' + item['highs'],
                                              "Low" + ':' + '\t' + item['lows']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "High", "Low"])
                                # data3.append(self.getMergedHeader())
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['highs']),
                                                  str(childapp['trace_breakdown']['lows'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('INNERGRID', (4, 0), (4, 1), 0.25, colors.white),  # removing grid for first row
                                    ('INNERGRID', (4, 2), (4, -1), 0.25, colors.white),  # removing grid for rest of med
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),
                                    ('BOX', (2, 0), (3, 0), 0.25, colors.black),
                                    ('BOX', (4, 2), (-1, -1), 0.25, colors.white),  # removing box for rest of med
                                    ('BOX', (0, 2), (-2, -1), 0.25, colors.black),
                                ])
                        else:  # if high/med != 0, check if low = 0
                            if item['lows'] == '0':
                                data3.append([item['name'], item['score'], "High" + ':' + '\t' + item['highs'],
                                              "Med" + ':' + '\t' + item['meds']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "High", "Med"])
                                # data3.append(self.getMergedHeader())
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['highs']),
                                                  str(childapp['trace_breakdown']['meds'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('VALIGN',(0,0),(0,-1),'TOP'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('INNERGRID', (4, 0), (4, 1), 0.25, colors.white),  # removing grid for first row
                                    ('INNERGRID', (4, 2), (4, -1), 0.25, colors.white),
                                    # removing grid for rest of lows
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),
                                    ('BOX', (2, 0), (3, 0), 0.25, colors.black),
                                    ('BOX', (4, 2), (-1, -1), 0.25, colors.white),  # removing box for rest of lows
                                    ('BOX', (0, 2), (-2, -1), 0.25, colors.black),
                                ])
                            else:  # if just high/med/low != 0
                                data3.append([item['name'], item['score'], "High" + ':' + '\t' + item['highs'],
                                              "Med" + ':' + '\t' + item['meds'], "Low" + ':' + '\t' + item['lows']])

                                data3.append(["", "", "", "", ""])
                                data3.append(["Application", "Grade", "High", "Med", "Low"])
                                # data3.append(self.getMergedHeader())
                                for childapp in childapps:
                                    name = childapp['name']
                                    data3.append([name, "", str(childapp['trace_breakdown']['highs']),
                                                  str(childapp['trace_breakdown']['meds']),
                                                  str(childapp['trace_breakdown']['lows'])])
                                s = getSampleStyleSheet()
                                s = s["BodyText"]
                                s.wordWrap = 'CJK'

                                style2 = TableStyle([  # ('ALIGN',(1,1),(-2,-2),'RIGHT'),
                                    # ('VALIGN',(0,0),(0,-1),'TOP'),
                                    # ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                                    # ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                                    # ('HALIGN',(0,-1),(-1,-1),'CENTER'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('INNERGRID', (0, 0), (1, 0), 0.25, colors.white),
                                    ('INNERGRID', (0, 1), (5, 1), 0.25, colors.white),
                                    ('BOX', (0, 0), (1, 0), 0.25, colors.white),
                                    ('BOX', (2, 0), (4, 0), 0.25, colors.black),
                                    ('BOX', (0, 2), (-1, -1), 0.25, colors.black),
                                ])

                    data2 = []

                    for i, row in enumerate(data3):
                        rows = []
                        if i == 0:
                            s.fontName = 'Helvetica-Bold'
                        else:
                            s.fontName = 'Helvetica'

                        for j, cell in enumerate(row):
                            if i == 0 and j == 1:
                                s.fontName = 'Helvetica-Bold'
                            elif i is not 2:
                                if row[1] is not "" and j == 0:
                                    s.fontName = 'Helvetica-Bold'
                                else:
                                    s.fontName = 'Helvetica'
                            if cell == 'D' or cell == 'F':
                                rows.append(Paragraph(cell, s))
                            elif cell == 'C':
                                rows.append(Paragraph(cell, s))
                            elif cell == 'A' or cell == 'B':
                                rows.append(Paragraph(cell, s))
                            else:
                                rows.append(Paragraph(cell, s))
                        data2.append(rows)
                    t = Table(data2)
                    t.setStyle(style2)

                    # title = item['name']
                    # score = item['score']
                    # data3.append(Paragraph(title + ':' + '\t' + '\t' + '\t' + '\t' + '\t' + score, ParagraphStyle('h1', fontSize = 20, spaceAfter = 12)))
                    # elements.append(Paragraph(title + ':' + '\t' + '\t' + '\t' + '\t' + '\t' + score, ParagraphStyle('h1', fontSize = 20, spaceAfter = 12)))
                    # elements1.append(Paragraph("text", ParagraphStyle('h1')))
                    # elements3 = elements2 + elements1
                    # elements.append(elements3)
                    # print(elements)
                    # Send the data and build the file
                    elements.append(t)
                    elements.append(PageBreak())

            except Exception as e:
                print(e)
                continue
        doc.build(elements)


apps = data()
apps.generatePDF()
