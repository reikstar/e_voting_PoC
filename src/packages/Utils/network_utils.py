HEADERSIZE = 30

def get_socket_msg(_socket):
    try:
        msg_header = _socket.recv(HEADERSIZE)
        if not len(msg_header):
            return False
        
        msg_length = int(msg_header.decode('utf-8'))
        client_message = _socket.recv(msg_length)

        return client_message
    
    except Exception as e:
        print(f"Error handling socket message: {str(e)}")
        return False

def send_msg(_socket, data):
    
    if not isinstance(data,bytes):
        data = bytes(data, 'utf-8')
    
    msg = bytes(f'{len(data):<{HEADERSIZE}}', 'utf-8') + data

    try:
        _socket.send(msg)
    except Exception as e:
        print(f"Error handling client message: {str(e)}")
