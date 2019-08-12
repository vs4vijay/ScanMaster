from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
# from gvm.errors import GvmError

class OpenVASScanner:
    
    def __init__():
        pass
    
    def start(self):
        print('[+] Starting OpenVAS Scan')


        # https://gvm-tools.readthedocs.io/en/latest/scripting.html


        # path = '/var/run/gvmd.sock'
        connection = UnixSocketConnection()
        transform = EtreeTransform()
        gmp = Gmp(connection, transform=transform)

        # Retrieve GMP version supported by the remote daemon
        version = gmp.get_version()

        # with gmp:
        #     print(gmp.get_version())

        # Prints the XML in beautiful form
        pretty_print(version)

        # Login
        gmp.authenticate('foo', 'bar')

        # Retrieve all tasks
        tasks = gmp.get_tasks()

        # Get names of tasks
        task_names = tasks.xpath('task/name/text()')
        pretty_print(task_names)

    def stop(self):
        pass
    
    def list_scans(self):
        pass