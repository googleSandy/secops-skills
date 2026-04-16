# Source: https://docs.cloud.google.com/chronicle/docs/investigation/udm-search-time-range

# Use UDM Search time range and manage queries
Supported in:    Google secops   SIEM     Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
Note: This feature is not available to all customers in all regions.
Google Security Operations gives you the ability to search through up to a year of the enterprise data stored in your account. It also includes a number of tools that let you run multiple UDM search queries and later retrieve and share the results of those queries.
## Use UDM to search up to a year of data
You can conduct a UDM search on up to one year of your UDM data. To adjust the time period for your UDM search, complete the following steps:  Go to Investigation > SIEM Search. Click the time selector field to open the time selector dialog. From the Range tab (the default tab), adjust the time range by selecting any of the options from Last 5 minutes to Last year. Use the Start and End fields to choose a more specific date range (for example, the first two weeks in November).  Adjust the times by selecting specific start and end values, for example, 03:00 and 08:30. Click Apply and then click Run Search.
## Run concurrent searches and manage search queries
Concurrent searches and stored results require the search history feature to be active. To ensure that search history is on, complete the following steps:
Go to Investigation > SIEM Search.
Click History. If the Search History Is Disabled message is displayed, proceed to the next step. If you don't see this message, then Search History is already enabled for your account.
Click  more_vert  and select Opt into search history.
### Manage search queries
You can run multiple UDM searches, retrieve previous query search results, and share your query results with other members of your team:
Run multiple UDM searches: While a search query is in progress, you can run additional searches in the query editor. Google SecOps continues running your previous searches and runs the new searches in parallel.
View query results: Scroll through the query history and select search results within 24 hours of running a query. Click History and select one of your queries from the list.
In-progress queries are displayed with a circular status icon. Completed queries are displayed with a green check mark icon, along with a counter indicating the number of events returned by the query. Click a completed query to display the results. These results are cached and only include the data available at query run time. However, you can click  cached  Rerun to run the query against the latest data. This new run is added to the search history and the results are made available when the query completes.
Share query results: Copy the URL of the query results to share them with other users.
When search results are stored, the RBAC scopes of the user who ran the search are stored with them. When these results are viewed by another user, the viewer's RBAC scope is compared to the stored scopes. If the viewer's scopes are more restrictive, an error is displayed and they won't be able to view the results.
Stored search results expire 24 hours after a query is run. However, your search query is still available in the History pane. You can rerun your searches and the results are made available for up to 24 hours after the query run time.