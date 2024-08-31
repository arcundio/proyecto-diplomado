// src/components/FileItem.js
import React from 'react';
import './FileItem.css';

function FileItem({ fileName, fileSize, iconType }) {
    return (
        <div className="file-item">
            <img src={`/icons/${iconType}.png`} alt={fileName} className="file-icon" />
            <div className="file-info">
                <div className="file-name">{fileName}</div>
                <div className="file-size">{fileSize}</div>
            </div>
        </div>
    );
}

export default FileItem;
