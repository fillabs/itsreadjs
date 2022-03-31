import * as fs from 'fs';
import {inspect} from 'util';
import {ItsSecRead as reader} from './itsread.mjs';

var a, l;

a = fs.readFileSync(process.argv[2]);
l = await reader(a);
l.forEach(async (os) => {

    console.log(inspect(os, {
        depth: null,
        customInspect: true,
        maxArrayLength: null,
        showHidden: false
    }));

    let signer;
    if (process.argv[3]) {
        try {
            a = fs.readFileSync(process.argv[3]);
            l = await reader(a);
            if (l.length > 0)
                signer = l[0];
        } catch (e) {
            console.log(e);
            signer = undefined;
        }
    }

    if (os.constructor.name === "Ieee1609Dot2Data") {
        console.log("TbsHash: " + inspect(os.content.signedData.tbsHash, {
            depth: null,
            customInspect: true,
            maxArrayLength: null,
            showHidden: false
        }));

        if (signer === undefined) {
            if (Array.isArray(os.content.signedData.signer.certificate) && os.content.signedData.signer.certificate.length > 0)
                signer = os.content.signedData.signer.certificate[0];
        }
    }

        // verify message
    try {
        os.verify(signer).then(passed=>{
            if (passed) {
                console.log("Signature verification passed");
            } else {
                console.log("Signature verification failed");
            }
        });
    }
    catch (e) {
        console.log("error:" + e.toString());
    }
});
