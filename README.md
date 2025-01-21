# Code2Flow en OWASP Threat Dragon

Integrar automáticamente el flujo generado en Code2Flow en OWASP Threat Dragon


(pytm) ┌──(pytm)(mj㉿viewnext)-[~/Documents/Environments/pytm/Documentos/Scripts]
└─$ which python
/home/mj/Documents/Environments/pytm/bin/python

(pytm) ┌──(pytm)(mj㉿viewnext)-[~/Documents/Environments/pytm/Documentos/Scripts]
└─$ python
Python 3.12.8 (main, Dec 13 2024, 13:19:48) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pytm import TM
>>> print(dir(TM))
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_actors', '_add_threats', '_assets', '_boundaries', '_check_duplicates', '_colormap', '_data', '_dfd_template', '_duplicate_ignored_attrs', '_elements', '_flows', '_init_threats', '_process', '_seq_template', '_sf', '_stale', '_threats', '_threatsExcluded', 'assumptions', 'check', 'description', 'dfd', 'findings', 'ignoreUnused', 'isOrdered', 'mergeResponses', 'name', 'onDuplicates', 'process', 'report', 'reset', 'resolve', 'seq', 'sqlDump', 'threatsFile']
>>> exit ()

(pytm) ┌──(pytm)(mj㉿viewnext)-[~/Documents/Environments/pytm/Documentos/Scripts]
└─$ pip list
Package  Version
-------- ----------
graphviz 0.20.3
pip      24.3.1
pydal    20241204.1
pytm     1.3.1

(pytm) ┌──(pytm)(mj㉿viewnext)-[~/Documents/Environments/pytm/Documentos/Scripts]
└─$ python generate-threat-model.py
Generando el informe del modelo...
Informe generado exitosamente.
Exportando el modelo a /home/mj/Documents/Environments/pytm/Documentos/Evidencias/threat_model.json...
Modelo exportado correctamente.

(pytm) ┌──(pytm)(mj㉿viewnext)-[~/Documents/Environments/pytm/Documentos/Scripts]
└─$ 
