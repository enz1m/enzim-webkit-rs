(() => {
    const result = document.createElement('pre');
    result.id = 'dictionary-result';
    document.body.append(result);
    (async () => {
        const expected = document.querySelector('meta[name=body-sha256]').content;
        const phase = new URL(location.href).searchParams.get('case');
        const records = [];
        if (ACQUIRE_DICTIONARY) {
            const response = await fetch('/dictionary?case=' + phase);
            await response.arrayBuffer();
            await new Promise(resolve => setTimeout(resolve, 150));
        }
        for (let index = 0; index < 3; ++index) {
            const start = performance.now();
            const response = await fetch('/resource/update?case=' + phase + '&index=' + index);
            const body = await response.arrayBuffer();
            const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', body))].map(byte => byte.toString(16).padStart(2, '0')).join('');
            if (hash !== expected) throw Error('decoded response differs');
            records.push({ms: performance.now()-start, encoding:response.headers.get('Content-Encoding'), encodedBytes:Number(response.headers.get('Content-Length')), decodedBytes:body.byteLength});
        }
        const expectedEncoded = Number(document.querySelector(EXPECT_DICTIONARY ? 'meta[name=dcz-bytes]' : 'meta[name=br-bytes]').content);
        if (records.some(record => record.encodedBytes !== expectedEncoded)) throw Error('dictionary negotiation differs: ' + JSON.stringify(records));
        let corruptRejected = null;
        if (EXPECT_DICTIONARY) {
            try {
                const response = await fetch('/resource/corrupt?case=' + phase);
                await response.arrayBuffer();
                corruptRejected = false;
            } catch (_) { corruptRejected = true; }
            if (!corruptRejected) throw Error('corrupt dictionary hash was accepted');
        }
        result.textContent = JSON.stringify({passed:true, phase, records, corruptRejected});
    })().catch(error => { result.textContent = JSON.stringify({passed:false, error:String(error)}); }).finally(() => { result.dataset.done = '1'; });
    return true;
})()
