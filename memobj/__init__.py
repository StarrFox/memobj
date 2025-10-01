import logging

from .allocation import Allocation, Allocator
from .object import MemoryObject
from .process import Process, WindowsProcess
from .property import *

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

del logging
del logger
