from .Kyber512 import Kyber512Parameters
from .Kyber768 import Kyber768Parameters
from .Kyber1024 import Kyber1024Parameters

parameter_sets = {
    "Kyber512": Kyber512Parameters,
    "Kyber768": Kyber768Parameters,
    "Kyber1024": Kyber1024Parameters,
}