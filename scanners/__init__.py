# This __init__.py file is intended to serve as a central point for importing scanner implementations
# and potentially providing common functionality across different scanner types.

# Importing scanner classes to make them available for use elsewhere in the project
from .nexpose_scanner import NexposeScanner
from .openvas_scanner import OpenVASScanner
from .zap_scanner import ZapScanner

# Potential common functionality or base classes could be defined here if needed
