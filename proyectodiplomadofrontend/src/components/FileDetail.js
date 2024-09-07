import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import './FileDetail.css';

function FileDetail() {
    const { hash } = useParams();
    const navigate = useNavigate();
    const [fileDetails, setFileDetails] = useState({});
    const [shareEmail, setShareEmail] = useState('');
    const [isSigned, setIsSigned] = useState(false);
    const [shareMessage, setShareMessage] = useState('');
    const [shareMessageColor, setShareMessageColor] = useState(''); // 'green' or 'red'
    const [isFileOwner, setIsFileOwner] = useState(false);
    const [selectedFile, setSelectedFile] = useState(null);

    useEffect(() => {
        const fetchFileDetails = async () => {
            if (hash) {
                try {
                    // Fetch file details
                    const fileResponse = await fetch(`https://localhost:8505/files/${hash}`);
                    const fileData = await fileResponse.json();
                    setFileDetails(fileData);
                    setIsSigned(fileData.isSigned);

                    // Fetch owner details
                    const token = localStorage.getItem('jwt');
                    const userID = localStorage.getItem('userID');
                    const ownerResponse = await fetch(`https://localhost:8505/file/${hash}/owner`, {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    const ownerData = await ownerResponse.json();
                    setIsFileOwner(ownerData.isOwner);

                    // Check if file is signed
                    const signatureResponse = await fetch(`https://localhost:8505/verify-signature`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`,
                        },
                        body: JSON.stringify({
                            userId: parseInt(userID, 10), // Convierte userID a número entero
                            fileId: parseInt(hash, 10)    // Convierte fileId (hash) a número entero
                        }),
                    });
                    const signatureData = await signatureResponse.json();
                    setIsSigned(signatureData.signed);
                } catch (error) {
                    console.error('Error fetching file details:', error);
                }
            }
        };

        fetchFileDetails();
    }, [hash]);

    const handleShare = () => {
        const jwtToken = localStorage.getItem('jwt');
        const userID = localStorage.getItem('userID');

        if (!hash) {
            console.error('File ID (hash) is missing.');
            setShareMessage('File ID is missing.');
            setShareMessageColor('red');
            return;
        }

        if (!shareEmail) {
            console.error('Share email is missing.');
            setShareMessage('Share email is missing.');
            setShareMessageColor('red');
            return;
        }

        fetch(`https://localhost:8505/share-file/${hash}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${jwtToken}`,
            },
            body: JSON.stringify({
                email: shareEmail,
                fileID: parseInt(hash), // Ensure fileID is an integer
                userID: parseInt(userID) // Ensure userID is an integer
            }),
        })
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error('Error sharing file');
                }
            })
            .then(data => {
                setShareMessage('File shared successfully');
                setShareMessageColor('green');
                setShareEmail('');
            })
            .catch(error => {
                console.error('Error sharing file:', error);
                setShareMessage('Error sharing file');
                setShareMessageColor('red');
            });
    };

    const handleSign = (event) => {
        event.preventDefault();

        if (!selectedFile) {
            console.error('Private key file is missing.');
            return;
        }

        const jwtToken = localStorage.getItem('jwt');
        const userID = localStorage.getItem('userID');

        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('fileID', hash);
        formData.append('userID', userID);

        fetch('https://localhost:8505/sign', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${jwtToken}`,
            },
            body: formData,
        })
            .then(response => {
                if (response.ok) {
                    return response.text();
                } else {
                    throw new Error('Error signing file');
                }
            })
            .then(message => {
                alert(message);
            })
            .catch(error => {
                console.error('Error signing file:', error);
                alert('Error signing file');
            });
    };

    const handleDownloadKey = () => {
        const jwtToken = localStorage.getItem('jwt');
        const userID = localStorage.getItem('userID');

        fetch('https://localhost:8505/generateKeys', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${jwtToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: parseInt(userID, 10), keyName: 'private-key' }) // Adjust the key name if needed
        })
            .then(response => {
                if (response.ok) {
                    return response.blob();
                } else {
                    throw new Error('Error downloading key');
                }
            })
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'private-key.pem'; // Adjust the filename if needed
                document.body.appendChild(a);
                a.click();
                a.remove();
            })
            .catch(error => {
                console.error('Error downloading key:', error);
                alert('Error downloading key');
            });
    };

    return (
        <div className="file-detail-container">
            <button className="back-button" onClick={() => navigate(-1)}>X</button>
            <div className="file-info">
                <h2>{fileDetails.name}</h2>
                <p>Status: {isSigned ? 'Signed' : 'Not Signed'}</p>
            </div>
            <div className="share-file">
                <input
                    type="email"
                    value={shareEmail}
                    onChange={(e) => setShareEmail(e.target.value)}
                    placeholder="Enter email to share"
                />
                <button onClick={handleShare}>Share File</button>
                {shareMessage && (
                    <p style={{ color: shareMessageColor }}>{shareMessage}</p>
                )}
            </div>
            {isFileOwner && (
                <>
                    <form onSubmit={handleSign}>
                        <input
                            type="file"
                            accept=".pem"
                            onChange={(e) => setSelectedFile(e.target.files[0])}
                        />
                        <button type="submit">Sign File</button>
                    </form>
                    <button onClick={handleDownloadKey}>
                        <img src="/assets/key-favicon.png" alt="Download Key" />
                        Download Private Key
                    </button>
                </>
            )}
        </div>
    );
}

export default FileDetail;
