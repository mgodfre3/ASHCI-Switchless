# ASHCI-Switchless
 Deploy a 2 node switchless ASHCI Cluster

This configuration will help you deploy a 2 node cluster with a switchless configuration. As part of this deployment, you will need to:
*Install Azure Stack HCI on your Server Nodes
*Join your Server Nodes to the domain
*Provide Names to your Server Nodes
*Name your Management Adapters to "Managment Physical 1" and so on
*Set a Static IP Address on your "Management Physical 1" adapter
*Name your Storage Adapters to "SMB1" and so on.
*Provide a VSwitch Name
*Provide a Cluster Name
*Provide a Cluster IP Address
*Detirmine some Hardware Related Features


This deployment will deploy a vSwitch for Managment/Compute Traffic and then 2xSMB adapters, assumed to be connected directly to each other in a switchless configuration. THe Storage adapters are not ASSUMED to be connected to Top-of-Rack (TOR) Switch.

## Networking documentation
https://docs.microsoft.com/en-us/azure-stack/hci/concepts/host-network-requirements
 

## Viewing documents

Documents are rendered at the server and are viewable when received by the browser. Special styles and extended
formatting are used which prevent them from rendering properly as generalized Markdown. While you can browse them
here in the repo, they are not meant to render properly as GitHub document.

# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademarks

MICROSOFT, the Microsoft Logo, are registered trademarks of Microsoft Corporation. They can only be used for the purposes described in and in accordance with Microsoft’s Trademark and Brand guidelines published at https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general.aspx. If the use is not covered in Microsoft’s published guidelines or you are not sure, please consult your legal counsel.