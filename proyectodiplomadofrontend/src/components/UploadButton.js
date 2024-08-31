import React from 'react';
import './UploadButton.css';

const UploadButton = ({ onUpload }) => {
    const handleFileChange = (event) => {
        const files = event.target.files;
        if (files.length > 0) {
            onUpload(files[0]);
        }
    };

    return (
        <div className="upload-button">
            <label htmlFor="file-upload" className="upload-label">
                <img src="/icons/cloud-upload-alt.png" alt="Upload" />
            </label>
            <input
                type="file"
                id="file-upload"
                style={{ display: 'none' }}
                onChange={handleFileChange}
            />
        </div>
    );
};

export default UploadButton;
