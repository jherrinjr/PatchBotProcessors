# PatchBotProcessors
Part of PatchBot - three AutoPkg custom processors

Details can be found at https://github.com/Honestpuck/PatchBot

This is v3F.1 a fork of v3 with a number of features added from FresnoState made by James Herrin and Jacob Sales. 

Changes can be summarised:

- We made it so that when JSS downloads and updates the policies for new apps those apps are immediately available to all to install with name "Install Latest <appname>". 
- Therefore we made it so that in the recipe you can choose the format of the name of the dependent General Policy that the PST Policy relies on.
- We added the ability for PST policies to be deployed as prompt (automatic install) or Self Service.
- We added the feature for patchbot to read the recipe to determine pst policy distribution method.
- With the ability to deploy the PST policy as prompt we had to create a testTimeDB.json that tracks how long a version is in testing to control when it goes to Production.

This is v3. It has now been released to production.

Changes can be summarised:

 - Replaced the need for Move.py. All the checking to see if there is a test patch to move into production is now done in the Production processor.
 - There is a new constant in the Production code, `DEFAULT_DELTA` to set the default number of days between test and production.
 - There is a new constant in the Production code, `DEFAULT_DEADLINE`. The Production processor sets the Self Service deadline to this value every time it updates a "Stable" patch policy.
 - There is a new optional variable in Production `.prod` recipes called `delta` to set the number of days between test and production for that package.
- There is a new optional variable in Production `.prod` recipes called `deadline` to set the Self Service deadline for that package.

The code *should* run, it has been vigorously tested. There are still things to be done. Certainly the Production processor could be cleaned up as it it grabs information to check the delta then throws it all away so the process to move a package from test into production has to find it all again, that's less than optimal and makes unnecessary API calls.

Now that `delta` can be defined in a `.prod` recipe it is now possible to move a package from test into production from the command line. `autopkg run GoogleChrome.prod -k 'delta=-1'` will immediately move Google Chrome from testing into production, for example. You can do the same with `deadline`. 
`autopkg run GoogleChrome.prod -k 'delta=-1' -k 'deadline=1'` will move Google Chrome into production with a short Self Service deadline.

Regarding the "delta" and "deadline" variables. First, you can't set either to zero as it then becomes impossible to differentiate between a setting of `0` and the `0` the code gets when the variable is unset. For "delta" setting it to "-1" works as well as 0. For the deadline Jamf Pro does not accept zero or negative numbers, the lowest is `1` which seems acceptable.
