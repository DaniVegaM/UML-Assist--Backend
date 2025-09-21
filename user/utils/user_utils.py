import uuid
from user.models import User

def generate_unique_username(base_username):
    """
    Genera un username único basado en un username base.
    Si el username ya existe, agrega un sufijo numérico o UUID.
    """
    username = base_username
    counter = 1
    
    while User.objects.filter(username=username).exists():
        username = f"{base_username}_{counter}"
        counter += 1
        
        if counter > 999:
            username = f"{base_username}_{uuid.uuid4().hex[:8]}"
            break
    
    return username

