# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/manage-parser-updates

# Manage prebuilt and custom parsers
Supported in:    Google secops   SIEM
This document provides guidance on how to manage parsers within Google Security Operations. It details how to handle updates to prebuilt and custom parsers, create parser extensions, and control access to parser management features:  Manage prebuilt parser updates Manage prebuilt parser versions Manage custom parsers Create an extension Control access to parser management  Note: Only UTF-8 characters are supported in UDM field mappings. Using other encodings can cause parsing failures and make logs unsearchable.
### Parser types
Understanding parser types and their functions:    Parser type Description     Prebuilt Parsers created by Google SecOps that include built-in mappings to transform original log data into UDM fields.   Prebuilt extended A prebuilt parser created by customers with additional mapping instructions to extract additional data from an original raw log and insert it into the UDM record.   Custom A parser that is not prebuilt and has custom data mapping instructions to transform original log data to UDM fields.    Custom extended A custom parser with additional mapping instructions that uses a parser extension to extract additional data from an original raw log and insert it into the UDM record.
### Parser support levels
Google SecOps offers these levels of parser support:    Parser Type Description and Support     Premium parsers Google SecOps provides high-quality parsers from the most widely used, high-volume data sources. Customer requests for premium parsers are typically processed within a few days.   Standard parsers For other supported data sources, Google SecOps offers best-effort support. Requests for new field mappings are handled as feature requests and are part of the product backlog. To meet immediate needs, you can use the self-service parser extensions and Auto-extract capabilities.   Custom-built parsers and extensions Google SecOps does not offer support for these. We recommend that you manage this either independently or with assistance from Google partners.
For a complete list of Premium and Standard parsers, see Default Parser Configuration.
For an overview of parsing raw logs to the Unified Data Model (UDM) format, see Overview of log parsing. Note: Google handles all requests for new prebuilt parsers as feature requests.
## Manage prebuilt parser updates
Google SecOps typically updates its prebuilt parsers during the fourth week of each month. These updates are first made available to customers for early access and testing. As upcoming parser updates become available, they are marked as Pending update in the parser list. You can examine the difference between the earlier and the newer parser versions, or make the parser update active early to test it, or skip the update and create a custom parser. Important: This feature requires automatic parser updates to be active. To turn on this setting, see Opt in and out of automatic parser updates.
To view the pending update do the following:
Log in to your Google SecOps instance.
Select Settings > SIEM Settings > Parsers.
Click filter_alt Filter.
Select Prebuilt, Active, and Prebuilt Extended from the list.
A list of active (default), prebuilt parsers displays. Upcoming parser updates are marked as Pending in the Update column.
Click more_vert Menu and select View pending update from the list.
The Compare parsers page appears. Here, you can view the following:
The code difference between current and the upcoming parser version
Analyze the impact of the upcoming parser version on your detection rules
The changelogs in the Change logs tab
The generated UDM event for the sampled raw log
The date and time the parser was created
The date and time the parser code was last updated
You can either make the parser update active early, skip the update and create a custom parser, or wait for the update to be auto-applied during the fourth week of the month.
### Make the parser update active early
The parser management feature lets you make the parser update active early. For example, if you want to test it.
To make the parser update active early, follow these steps:
On the Compare parsers page, click Make parser update active.
The Confirm parser update dialog appears.
Click Confirm.
The parser is activated for the normalization process after 20 minutes. Note: This parser version remains active until the next release cycle.
### Skip prebuilt parser updates
To skip the current and future prebuilt parser updates, create a custom parser as follows:
On the Compare parsers page, click Skip update.
The Skip update and create custom parser window appears.
Click Create custom parser.
For the Type of parser to start with, select either the current Prebuilt Parser, or the Pending Parser Update.
Click Create. Note: If a custom parser already exists for this log source, you cannot create another one. The following message is displayed, A custom parser already exists for this log source.
The selected version is activated for the normalization process after 20 minutes. It appears as Custom and Active in the parsers list on the Parsers page. The earlier prebuilt version appears as Prebuilt and Inactive. Note: All future prebuilt parser updates remain visible, but they're not applied unless you disable the custom parser and revert to the prebuilt version.
### Revert an early update of the prebuilt parser
If you activated the parser update early, you can still revert to the previous version until the fourth week of the month, when the update is automatically activated.
To switch back to the previous parser version, follow these steps:
From the apps Application menu, select Settings > Parsers.
Click more_vert Menu against the parser that you want to revert.
Click View.
The View prebuilt parser page appears.
Click Revert to previous version.
The Revert to previous dialog appears. You can click Compare Parsers on the dialog to see the difference between the current and the previous versions.
Click Confirm to revert the parser to its previous version.
The parser is reverted to its previous version after 20 minutes.
### Analyze the impact of the upcoming parser version
Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
Note: This feature is not available to all customers in all regions.
The impact check lets you assess the potential impact of the upcoming parser version on your detection rules before applying the changes. For any negatively affected rules, you can follow the links to investigate and update your rules accordingly.
For single-event rules, the analysis checks the detections that your detection rules generated over the last 30 days. It runs both the current and the upcoming parser versions on the events corresponding to those detections. This process regenerates the detections to check for mismatches.
For multi-event rules, the analysis uses a sample of your events rather than all events to perform a heuristic analysis. If events don't match, this analysis marks the outcome as Potentially failing.
To run an analysis of the impact of the upcoming parser version on your detection rules, do the following:  In the Google SecOps Console, go to Settings > SIEM Settings > Parsers. Select a specific Log type (prebuilt parser). Select one of the parser update options: Update to latest version, Rollback to last used version, or Opt-in to a Release Candidate. Go to the parser Impact tab and click Check impact on rules. The impact check may take some time to complete.
Upon completion, the system displays the following:  Parser metadata and a list of rules that the new version affects, detailing the rule type and the UDM fields showing differences.
The system categorizes any negatively affected rules as follows:  Failing: The new parser did not raise a detection, but the current parser did. Potentially failing: Rules (including multi-event) where UDM fields in the rule logic have changed. You must further investigate these rules.
For each of these, follow the link to the rule editor to investigate and edit the rule to get it to work with the new parser version.
## Manage prebuilt parser versions
Google SecOps provides and maintains prebuilt parsers to make sure your logs are parsed correctly. You can control how new parser versions are applied in your environment to meet your organization's needs.
This section describes the full parser version management lifecycle in Google SecOps. This includes opting in and out of automatic updates, comparing the logic between versions, manually updating to new versions, and rolling back to previous versions. Note: You can preview Google prebuilt parsers to test new versions. However, you cannot use the preview tool to test an updated prebuilt parser while you have an active custom parser running. You must deactivate your custom parser and revert to using a prebuilt one.
### Opt in and out of automatic parser updates
If you turn off automatic updates, the parser stays on its current version until you turn on auto-updates or manually update it. To turn off automatic updates, do the following:
From the apps Application menu, select Settings > Parsers.
Click more_vertMenu for the required prebuilt parser.
Click Turn off auto updates.
When automatic updates are enabled, the parser updates with every new stable release. To turn on automatic updates, do the following:
From the apps Application menu, select Settings > Parsers.
Click more_vertMenu for the required prebuilt parser.
Click Turn on auto updates.  Important: Opting in to a preview parser requires that automatic updates are active and that the parser is on the latest version. Disabling updates removes the preview option and restores the last used stable version for that log type.
### Update a parser version manually
If automatic updates are off, you can choose when to update a parser to a new version. This lets you review changes before applying them. Note: You can only upgrade to the latest parser version and not any versions in between. To update a parser, do the following:
From the apps Application menu, select Settings > Parsers.
Click more_vertMenu for the required parser.
Select Update to latest version.
The Compare parsers page appears. You can view the following:
The code difference between the current and the new parser version.
The Change log tab, which summarizes changes.
The UDM output for the sampled raw log. To test the output against a different log, click edit Edit to edit the sampled raw log.
The date and time the parser code last updated.
Click Update parser to update it to the latest version.
### Roll back a parser version
You can revert a parser to the version that you last used, regardless of its automatic update status. To roll back a parser version, do the following:
From the apps Application menu, select Settings > Parsers.
Click more_vertMenu for the required parser.
Select Roll back to last used version.
The Compare parsers page appears. You can view the following:
The code difference between the current and the last used parser version.
The Change log tab, which shows changes.
The UDM output for the sampled raw log. To test the output against a different log, click edit Edit to edit the sampled raw log.
The date and time the parser code last updated.
Click Proceed to roll back to revert to the last used version.
The parser rolls back to the last version you used. For example, if you upgraded from version 17.0 to 24.0, rolling back will return you to 17.0, not 23.0.
You can perform only one consecutive rollback. After you perform a rollback, the Roll back option is no longer available. Note: Parser updates take about 30 minutes. During this time, you might experience temporary inconsistencies in event parsing.
### Support policy for previous parser versions
Only the latest stable version of a prebuilt parser receives bug fixes and enhancements. If you disable automatic updates and remain on an earlier parser version, that version doesn't receive patches or updates. If you report issues with this earlier version, the next stable release includes the fix. You must manually upgrade your parser to the latest stable version to receive the fix.
## Custom parsers
Google SecOps lets you create custom parsers for cases where a prebuilt parser isn't available or when you want more control. Custom parsers appear in the parsers list, alongside prebuilt parsers.
Common use cases include:
Ingesting log data for a log type that doesn't have a prebuilt parser.
Use one of the following methods:  Create a custom parser based on mapping instructions to raw logs. Create a custom parser based on an existing parser.
Create a custom parser in order to skip prebuilt parser updates.
### Create a custom parser based on mapping instructions
You can create a custom parser by writing code that converts the original raw log to a UDM record.
Additional reading:  For more information about the structure of a parser, see Overview of log parsing. For more information about parser syntax, see Parser syntax reference.
When creating a parser, aim to populate as many important UDM fields as possible.
Go to Settings.
Go to SIEM Settings.
Click Create Parser.
Select an appropriate log source from the Log Source list.
Select Start with Raw Logs Only to create a new parser according to your requirements.
Click Create.
Enter your code in the Parser Code Terminal. For more information, see Create a code snippet mapping instruction.
Note: Make sure that your custom parser logic correctly maps and produces valid, current timestamps. If a custom parser incorrectly maps timestamps to a date outside of your standard retention window, the data is successfully ingested but will remain unsearchable in the user interface. Since search features rely on event timestamps for filtering, data mapped to an incorrect date is effectively invisible despite successful ingestion.
Optional: Click edit Edit to edit the existing raw log or copy.
Optional: Click refresh Load to load the latest raw log.
Click Preview to view the UDM output. An error message is displayed if the code is incorrect.
In the preview, you can use the statedump filter plugin to validate a parser's internal state. For more information, see Validate data using statedump plugin.
Click Validate to validate the custom parser.
The validation process may take a few minutes, so we recommend that you preview the custom parser first, make changes if required, and then validate the custom parser.
Click Submit.
The parser is activated for the normalization process after 20 minutes.
### Create a custom parser based on an existing parser
Use an existing parser as a template to create a new custom parser. This method supports only the code-based approach. To get started, follow these steps:
From the apps Application menu, select Settings > Parsers.
Click Create Parser.
Select an appropriate log source from the Log Source list.
Select Start with an Existing Prebuilt Parser to use an existing parser as a base to create a new custom parser. Note: If the selected log source does not have a prebuilt parser then this option is not displayed.
Click Create.
Edit your code in the Parser Code Terminal. For more information, see Create a code snippet mapping instruction.
Optional: Click edit Edit to edit the raw log.
Optional: Click refresh Refresh to refresh the raw log.
As you add code to build the parser, click Preview to view the UDM output. An error message is displayed if the code is incorrect.
In the preview, you can use the statedump filter plugin to validate the internal state of a parser. For more information, see Validate data using statedump plugin.
Click Validate to validate the custom parser.
The validation process may take a few minutes, so we recommend that you preview the custom parser first, make changes if required, and then validate the custom parser.
Click Submit.
The parser is activated for the normalization process after 20 minutes.
### Make a custom parser inactive
From the apps Application menu, select Settings > Parsers.
Click more_vert Menu against the parser that you want to make inactive and select Make inactive from the list.
The Make parser inactive dialog appears.
Click Make inactive.
The custom parser is deactivated and the current prebuilt parser version is activated after 20 minutes. The prebuilt parser now becomes the default parser.
### Delete a custom parser
From the apps Application menu, select Settings > Parsers.
Click more_vert Menu against the custom parser that you want to delete and select Delete from the list. Note: You cannot delete a prebuilt parser.
The Delete custom parser dialog appears.
Click Delete.
The custom parser is deleted and the current prebuilt parser version is activated after 20 minutes.
## Create an extension
Parser extensions provide a flexible way to extend the capabilities of existing prebuilt (default) parsers and custom parsers. They don't replace prebuilt or custom parsers. Instead, they enable the seamless extraction of additional fields from the original raw log into the UDM record. A parser extension is different from a custom parser.
To create a parser extension, see Using parser extensions.
## Control access to parser management
By default, users with Administrator and Editor roles can manage parser updates. New permissions can be granted to control who can view and manage these updates.
For more information about managing users and groups, or assigning roles, see the role-based access control user guide.