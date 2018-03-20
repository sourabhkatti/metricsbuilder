# Contrast UI Metrics Builder
Retrieves metrics from the Contrast UI. 

## How to Run the Script

### Specify Contrast UI connection details

Edit the scripts.properties file and specify the following information for your organization.
```python
ORGANIZATION_ID = ""
TEAMSERVER_URL = ""
API_KEY = ""
SERVICE_KEY = ""
USERNAME = ""
```
Alternatively, pass them in as commandline args (these will override the above variable values)

```python
python3 metricsbuilder.py -i <ORG_ID> -t <TEAMSERVER_URL> -a <API_KEY> -s <SERVICE_KEY> -u <USERNAME>
```

### Run command to retrieve metrics
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
