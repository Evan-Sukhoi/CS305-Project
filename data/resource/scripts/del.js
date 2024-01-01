function deleteFile(filePath) {
    if (confirm("Are you sure you want to delete this file?")) {
        fetch(`/delete?path=${filePath}`,{
            method: 'POST'
        })
        .then(response => {
            if (response.ok) {
                alert('Successfully.');
                location.reload();
            } else if (response.status == 403) {
                alert('You don\'t have permission to delete this file or folder.');
            } else if (response.status == 404) {
                alert('The file or folder you are trying to delete does not exist.');
            } else if (response.status == 409) {
                alert('The folder is not empty.');
            } else {
                alert('An error occurred while trying to delete the file. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while trying to delete the file.');
        });
    }
}

function uploadFile(filePath) {
    // 创建一个 input 元素
    const input = document.createElement('input');
    input.type = 'file';

    // 当文件选择后触发的事件
    input.addEventListener('change', function() {
        const file = input.files[0]; // 获取用户选择的文件

        const formData = new FormData();
        formData.append('file', file); // 将文件添加到 FormData 中

        // 使用 fetch 发送 POST 请求
        fetch(`/upload?path=${filePath}`, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (response.ok) {
                alert('Successfully.');
                location.reload();
            } else if (response.status == 403) {
                alert('You don\'t have permission to upload files here.');
            } else if (response.status == 404) {
                alert('The folder you are trying to upload to does not exist.');
            } else {
                alert('An error occurred while trying to upload the file. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while trying to upload the file.');
        });
    });

    // 触发点击事件，弹出文件选择框
    input.click();
}

function makeDir(filePath) {
    const dirName = prompt('Please enter the folder name:');
    if (dirName) {
        fetch(`/mkdir?path=${filePath}/${dirName}`,{
            method: 'POST'
        })
        .then(response => {
            if (response.ok) {
                alert('Successfully.');
                location.reload();
            } else if (response.status == 403) {
                alert('You don\'t have permission to create folders here.');
            } else if (response.status == 404) {
                alert('The folder you are trying to create a folder in does not exist.');
            } else {
                alert('An error occurred while trying to create the folder. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while trying to create the folder.');
        });
    }
}

function rangeDownload(filePath, contentLength, fileName) {
    console.log("range download");
    const range = 102400; // 100KB
    const rangePairs = [];
    const totalRanges = Math.ceil(contentLength / range);
    console.log(totalRanges);
    
    // Function to download each range and concatenate the responses
    const downloadRange = (start, end) => {
        const rangeHeaders = `bytes=${start}-${end}`;
        return fetch(filePath, {
            method: 'GET',
            headers: {
                'Range': rangeHeaders
            }
        }).then(response => response.arrayBuffer());
    };

    // Create an array of promises for each range
    for (let i = 0; i < totalRanges; i++) {
        const start = i * range;
        const end = (i === totalRanges - 1) ? contentLength - 1 : (i + 1) * range - 1;
        rangePairs.push(downloadRange(start, end));
    }

    // After all promises resolve, concatenate the array buffers and save the file
    Promise.all(rangePairs)
        .then(responses => {
            const combinedArrayBuffer = new Uint8Array(contentLength);
            let offset = 0;
            responses.forEach(response => {
                combinedArrayBuffer.set(new Uint8Array(response), offset);
                offset += response.byteLength;
            });

            // Convert array buffer to Blob
            const combinedBlob = new Blob([combinedArrayBuffer], { type: 'application/octet-stream' });

            // Create a download link and trigger download
            const downloadLink = document.createElement('a');
            downloadLink.href = URL.createObjectURL(combinedBlob);
            downloadLink.download = fileName || 'downloaded_file'; // Ensure a default filename
            downloadLink.click();
        })
        .catch(error => {
            console.error('Error downloading ranges:', error);
        });
}
