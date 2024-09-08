import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './DataWindow.css';
import expedienteIcon from '../assets/expediente.png';
import documentoIcon from '../assets/documento.png';
import uploadIcon from '../assets/cloud-upload-alt.png';

function DataWindow() {
    const [sharedUsers, setSharedUsers] = useState([]);
    const [userFiles, setUserFiles] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [currentUserID, setCurrentUserID] = useState(null);
    const [selectedFile, setSelectedFile] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        // Obtener el ID del usuario desde el almacenamiento local
        const userID = localStorage.getItem('userID');
        setCurrentUserID(parseInt(userID, 10));  // Asegurarse de que sea un número

        // Obtener los usuarios que han compartido archivos con el usuario que ha iniciado sesión
        fetch('/shared-users', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('jwt')}`
            }
        })
            .then(response => response.json())
            .then(data => {
                console.log('Usuarios compartidos:', data); // Depuración
                // Incluir al usuario actual en la lista de usuarios compartidos
                const updatedUsers = [
                    ...data.map(user => ({
                        UserID: user.id,
                        email: user.email
                    })),
                    { UserID: parseInt(userID, 10), email: 'Tus archivos' } // Añadir usuario actual
                ];
                setSharedUsers(updatedUsers);
            })
            .catch(error => console.error('Error fetching shared users:', error));
    }, []);

    useEffect(() => {
        if (selectedUser !== null && currentUserID !== null) {
            if (selectedUser !== currentUserID) {
                // Obtener los archivos del usuario seleccionado si es distinto del usuario actual
                fetch(`/shared-files/${selectedUser}`, {
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
                    }
                })
                    .then(response => response.json())
                    .then(data => {
                        console.log('Archivos compartidos obtenidos:', data); // Depuración
                        setUserFiles(data);
                    })
                    .catch(error => console.error('Error fetching shared files:', error));
            } else {
                // Obtener todos los archivos del usuario actual
                fetch(`/files/${currentUserID}`, {
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('jwt')}`
                    }
                })
                    .then(response => response.json())
                    .then(data => {
                        console.log('Archivos del usuario actual:', data); // Depuración
                        setUserFiles(data);
                    })
                    .catch(error => console.error('Error fetching user files:', error));
            }
        }
    }, [selectedUser, currentUserID]); // Se ejecuta cuando `selectedUser` o `currentUserID` cambian

    const handleUserClick = (userID) => {
        console.log("Usuario seleccionado:", userID); // Depuración
        setSelectedUser(userID);  // Actualiza el usuario seleccionado con el ID correcto
    };

    const handleFileUpload = (event) => {
        const file = event.target.files[0];
        if (file && currentUserID) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('userID', currentUserID); // Usar el ID del usuario actual

            fetch(`/upload`, {
                method: 'POST',
                body: formData,
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('jwt')}`
                }
            })
                .then(response => {
                    if (response.ok) {
                        return fetch(`/files/${currentUserID}`, {
                            headers: {
                                'Authorization': `Bearer ${localStorage.getItem('jwt')}`
                            }
                        });
                    } else {
                        throw new Error('Error uploading file');
                    }
                })
                .then(response => response.json())
                .then(data => setUserFiles(data))
                .catch(error => console.error('Error uploading file:', error));
        }
    };

    const handleFileClick = (file) => {
        setSelectedFile(file);
        navigate(`/data/file/${file.ID}`); // Redirigir a /data/file/:id_file
    };

    return (
        <div className="container">
            <div className="data-window">
                <div className="user-list">
                    {sharedUsers.length === 0 ? (
                        <p>No users available</p> // Mensaje en caso de que no haya usuarios compartidos
                    ) : (
                        sharedUsers.map(user => (
                            <div
                                key={user.UserID}
                                className="user-item"
                                onClick={() => handleUserClick(user.UserID)}  // Llama a handleUserClick con el UserID correcto
                            >
                                {user.email} {/* Mostrar el email del usuario */}
                            </div>
                        ))
                    )}
                </div>
                <div className="file-list">
                    {userFiles.length === 0 ? (
                        <p>No files available</p> // Mensaje en caso de que no haya archivos
                    ) : (
                        userFiles.map((file) => (
                            <div key={file.ID} className="file-item" onClick={() => handleFileClick(file)}> {/* Usar file.ID como key */}
                                <img
                                    src={file.FileName.includes('png') ? expedienteIcon : documentoIcon}
                                    alt={file.FileName}
                                    className="file-icon"
                                />
                                <div className="file-info">
                                    <div>{file.FileName}</div>
                                    <div>{file.FileSize}</div>
                                </div>
                            </div>
                        ))
                    )}
                </div>
                <div className="upload-button">
                    <label htmlFor="file-upload">
                        <img src={uploadIcon} alt="Upload" className="upload-icon" />
                    </label>
                    <input
                        type="file"
                        id="file-upload"
                        style={{ display: 'none' }}
                        onChange={handleFileUpload}
                    />
                </div>
            </div>
        </div>
    );
}

export default DataWindow;
