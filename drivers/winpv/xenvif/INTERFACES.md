Interface Versions and PDO Revisions
====================================

It is important that introduction of a new API, introduction of a new
version of an existing API or retirement of an old version of an API is
managed carefully to avoid incompatibilities between clients and
providers. The general API versioning policy is described below:

Each distinct set of API versions exported by a bus driver maps to a PDO
revision. The DeviceID of each PDO created will specify the latest
revision supported and all others will be contained within the
HardwareIDs and CompatibleIDs. When a new version of an API is added,
a new PDO revision must be added. When a version of an API is removed
then ALL revisions that API version maps to must be removed. The mapping
of interface versions to PDO revisions is specified in the header file
include/revision.h in the bus driver source repository.

Whe introducing a new version of an interface in a bus driver it is good
practice to continue to support the previous version so it is not
necessary to simultaneously introduce a new PDO revision and retire a
previous one that child drivers may still be binding to.
Child drivers should, of course, always be built to use the latest
interface versions (which can be copied from the include directory in the
source repository of the bus driver providing them) but it may take
some time to make the necessary changes and deploy new builds of child
drivers and so some overlap is desirable.

To try to avoid installation of a version of a bus driver that is
incompatible with child drivers installed on a system. There is a check
in the pre-install phase in the co-intaller which compares the
MatchingDeviceId values for each child driver against the table in
include/revision.h in the bus driver source to make sure that the
matching revision number is present.
