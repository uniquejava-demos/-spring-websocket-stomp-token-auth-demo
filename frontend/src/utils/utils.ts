export const readBlobAsJSON = (blob: Blob): Promise<any> => {
    const fileReader = new FileReader()

    return new Promise((resolve, reject) => {
        fileReader.onerror = () => {
            fileReader.abort()
            reject()
        }

        fileReader.onload = () => {
            resolve(JSON.parse(fileReader.result as string))
        }

        fileReader.readAsText(blob)
    })
}
