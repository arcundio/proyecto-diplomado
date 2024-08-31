import React, { useState } from 'react';
import './DataWindow.css';
import expedienteIcon from '../assets/expediente.png';
import documentoIcon from '../assets/documento.png';
import uploadIcon from '../assets/cloud-upload-alt.png';  // Asegúrate de tener este icono en la carpeta assets

function DataWindow() {
    const [selectedUser, setSelectedUser] = useState(null);
    const [userFiles, setUserFiles] = useState({
        'Usuario 1': [
            { name: 'Archivo1.pdf', size: '15MB', type: 'normal' },
            { name: 'Archivo2.pdf', size: '20MB', type: 'locked' }
        ],
        'Usuario 2': [
            { name: 'Archivo3.pdf', size: '5MB', type: 'normal' }
        ]
    });

    const users = ['Usuario 1', 'Usuario 2'];

    const handleFileUpload = (event) => {
        const file = event.target.files[0];
        if (file && selectedUser) {
            const newFile = { name: file.name, size: `${(file.size / (1024 * 1024)).toFixed(2)}MB`, type: 'normal' };
            setUserFiles({
                ...userFiles,
                [selectedUser]: [...userFiles[selectedUser], newFile]
            });
        }
    };

    return (
        <div className="container">
            <div className="data-window">
                <div className="user-list">
                    {users.map(user => (
                        <div key={user} className="user-item" onClick={() => setSelectedUser(user)}>
                            {user}
                        </div>
                    ))}
                </div>
                <div className="file-list">
                    {selectedUser && userFiles[selectedUser] && userFiles[selectedUser].map((file, index) => (
                        <div key={index} className="file-item">
                            <img
                                src={file.type === 'normal' ? expedienteIcon : documentoIcon}
                                alt={file.name}
                                className="file-icon"
                            />
                            <div className="file-info">
                                <div>{file.name}</div>
                                <div>{file.size}</div>
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
