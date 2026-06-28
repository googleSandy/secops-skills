# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/configure-custom-parsers

# Configure custom parsers
Supported in:    Google secops   SIEM
This document provides guidance on how to create custom parsers for cases where a prebuilt parser isn't available or when you want more control. Custom parsers appear in the parsers list, alongside prebuilt parsers.
Common use cases include:
Ingesting log data for a log type that doesn't have a prebuilt parser.
Use one of the following methods:  Create a custom parser based on mapping instructions to raw logs. Create a custom parser based on an existing parser.
Create a custom parser in order to skip prebuilt parser updates.
## Create a custom parser based on mapping instructions
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
## Create a custom parser based on an existing parser
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
## Make a custom parser inactive
From the apps Application menu, select Settings > Parsers.
Click more_vert Menu against the parser that you want to make inactive and select Make inactive from the list.
The Make parser inactive dialog appears.
Click Make inactive.
The custom parser is deactivated and the current prebuilt parser version is activated after 20 minutes. The prebuilt parser now becomes the default parser.
## Delete a custom parser
From the apps Application menu, select Settings > Parsers.
Click more_vert Menu against the custom parser that you want to delete and select Delete from the list. Note: You cannot delete a prebuilt parser.
The Delete custom parser dialog appears.
Click Delete.
The custom parser is deleted and the current prebuilt parser version is activated after 20 minutes.
## Create an extension
Parser extensions provide a flexible way to extend the capabilities of existing custom parsers. They don't replace custom parsers. Instead, they enable the seamless extraction of additional fields from the original raw log into the UDM record. A parser extension is different from a custom parser.
To create a parser extension, see Using parser extensions.