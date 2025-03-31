critical_ports = [22, 3389, 21, 23, 445]

def check_initial_acess(port: str) -> bool:
    if port in critical_ports:
        return True
    return False
