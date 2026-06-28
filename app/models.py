from pydantic import BaseModel, field_validator
from typing import List, Optional
import re
import ipaddress

class UserCreate(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_valido(cls, v):
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username deve ter pelo menos 3 caracteres")
        if len(v) > 32:
            raise ValueError("Username deve ter no máximo 32 caracteres")
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("Username só pode conter letras, números e underscore")
        return v

    @field_validator("password")
    @classmethod
    def password_valida(cls, v):
        if len(v) < 6:
            raise ValueError("Password deve ter pelo menos 6 caracteres")
        if len(v) > 72:
            raise ValueError("Password deve ter no máximo 72 caracteres")
        return v

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanRequest(BaseModel):
    targets: List[str]
    ports: Optional[str] = "21,22,23,25,53,80,443,3306,5432,6379,8080"
    protocol: Optional[str] = "tcp"

    @field_validator("targets")
    @classmethod
    def targets_validos(cls, v):
        if not v:
            raise ValueError("A lista de targets não pode ser vazia")
        if len(v) > 10:
            raise ValueError("Máximo de 10 targets por requisição")
        
        targets_limpos = []
        for target in v:
            target = target.strip()
            if not target:
                raise ValueError("Target não pode ser vazio")
            
            try:
                net = ipaddress.ip_network(target, strict=False)
                
                if net.version != 4:
                    raise ValueError(f"O IP '{target}' é IPv6. A API suporta apenas IPv4.")
                    
            except ValueError as e:
                if "IPv6" in str(e):
                    raise ValueError(str(e))
                raise ValueError(
                    f"Alvo inválido: '{target}'. Domínios/Hostnames não são permitidos. "
                    f"Por favor, use apenas endereços IPv4 válidos (ex: 142.250.218.238 ou 192.168.0.0/24)."
                )
                
            targets_limpos.append(target)
        return targets_limpos

    @field_validator("ports")
    @classmethod
    def ports_validas(cls, v):
        if not v:
            raise ValueError("Ports não pode ser vazio")
        partes = v.split(",")
        if len(partes) > 100:
            raise ValueError("Máximo de 100 portas por requisição")
        for parte in partes:
            parte = parte.strip()
            if "-" in parte:
                limites = parte.split("-")
                if len(limites) != 2:
                    raise ValueError(f"Range de portas inválido: '{parte}'")
                try:
                    inicio, fim = int(limites[0]), int(limites[1])
                    if not (1 <= inicio <= 65535 and 1 <= fim <= 65535):
                        raise ValueError(f"Portas devem estar entre 1 e 65535: '{parte}'")
                    if inicio >= fim:
                        raise ValueError(f"Range inválido: início deve ser menor que fim: '{parte}'")
                except ValueError as e:
                    raise e
            else:
                try:
                    porta = int(parte)
                    if not (1 <= porta <= 65535):
                        raise ValueError(f"Porta deve estar entre 1 e 65535: '{parte}'")
                except ValueError:
                    raise ValueError(f"Porta inválida: '{parte}'")
        return v

    @field_validator("protocol")
    @classmethod
    def protocol_valido(cls, v):
        if v.lower() not in ("tcp", "udp"):
            raise ValueError("Protocol deve ser 'tcp' ou 'udp'")
        return v.lower()

class ScanResponse(BaseModel):
    id: int
    targets: List[str]
    status: str
    results: Optional[dict] = None
    created_at: str
