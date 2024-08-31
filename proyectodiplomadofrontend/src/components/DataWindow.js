import React, { useState, useEffect } from 'react';
import './DataWindow.css';
import expedienteIcon from '../assets/expediente.png';
import documentoIcon from '../assets/documento.png';
import uploadIcon from '../assets/cloud-upload-alt.png';

function DataWindow() {
    const [users, setUsers] = useState([]);
    const [userFiles, setUserFiles] = useState({});
    const [selectedUser, setSelectedUser] = useState(null);
    const [currentUserID, setCurrentUserID] = useState(null);

    useEffect(() => {
        // Obtener el ID del usuario desde el almacenamiento local
        const userID = localStorage.getItem('userID');
        setCurrentUserID(userID);

        // Obtener los usuarios al montar el componente
        fetch('http://localhost:8505/users')
            .then(response => response.json())
            .then(data => {
                console.log('Usuarios obtenidos:', data); // Depuración
                setUsers(data);
            })
            .catch(error => console.error('Error fetching users:', error));
    }, []);

    useEffect(() => {
        if (selectedUser) {
            // Obtener los archivos del usuario seleccionado
            fetch(`http://localhost:8505/files/${selectedUser}`)
                .then(response => response.json())
                .then(data => {
                    console.log('Archivos obtenidos:', data); // Depuración
                    setUserFiles(prevState => ({
                        ...prevState,
                        [selectedUser]: data
                    }));
                })
                .catch(error => console.error('Error fetching files:', error));
        }
    }, [selectedUser]);

    const handleFileUpload = (event) => {
        const file = event.target.files[0];
        if (file && currentUserID) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('userID', currentUserID); // Usar el ID del usuario actual

            // Depuración: mostrar contenido de FormData
            for (const [key, value] of formData.entries()) {
                console.log(`${key}: ${value}`);
            }

            fetch(`http://localhost:8505/upload`, {
                method: 'POST',
                body: formData,
            })
                .then(response => {
                    if (response.ok) {
                        return fetch(`http://localhost:8505/files/${currentUserID}`);
                    } else {
                        throw new Error('Error uploading file');
                    }
                })
                .then(response => response.json())
                .then(data => setUserFiles(prevState => ({
                    ...prevState,
                    [currentUserID]: data
                })))
                .catch(error => console.error('Error uploading file:', error));
        }
    };


    return (
        <div className="container">
            <div className="data-window">
                <div className="user-list">
                    {users.length === 0 ? (
                        <p>No users available</p> // Mensaje en caso de que no haya usuarios
                    ) : (
                        users.map(user => (
                            <div
                                key={user.UserID} // Usa UserID como key
                                className="user-item"
                                onClick={() => setSelectedUser(user.UserID)}
                            >
                                {user.email} {/* Mostrar el email del usuario */}
                            </div>
                        ))
                    )}
                </div>
                <div className="file-list">
                    {selectedUser && userFiles[selectedUser] && userFiles[selectedUser].map((file) => (
                        <div key={file.ID} className="file-item"> {/* Usar file.ID como key */}
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
                    ))}
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
