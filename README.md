# metricsbuilder

To run, either edit these parameters at the top of the script to have your connection details:

    # ORGANIZATION_ID = ""
    # TEAMSERVER_URL = ""
    # API_KEY = ""
    # SERVICE_KEY = ""
    # USERNAME = ""

Alternatively, pass them in as commandline args (these will override the above variable values)

python3 metricsbuilder.py -i <ORG_ID> -t <TEAMSERVER_URL> -a <API_KEY> -s <SERVICE_KEY> -u <USERNAME>

There are functions at the bottom of the script that can be commented out for various functions such as:

 vulnerabilities by app (ApplicationMetricsManager),
 vulnerabilities over time (dateTrendManager),
 etc...

    # controller.getServersWithNoApplications()
    # controller.getUsersNotLoggedInDays(days=30)
    # controller.getApplicationsWithNoGroup()
    # controller.getNeverLoggedInUsers()
    # controller.getOfflineServers()
    # controller.getUsersInGroups()
    # controller.metricsbuilder(days=90)
    # controller.dateTrendManager()
    # controller.getUsersInTaggedApplications()
    # controller.applicationMetricsManager()