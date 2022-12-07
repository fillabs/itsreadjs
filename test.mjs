import { DataCursor } from 'asnjs';
import * as fs from 'fs';
import { exit } from 'process';
import {inspect} from 'util';
import {ItsSecRead as reader} from './itsread.mjs';

var a, l;
var out_file, signer;
if(process.argv[2] == undefined){
    console.log( process.argv[0] + ' ' + process.argv[1] + ' <in_file> [signer] [-w out_file');
    exit(1);
}

for(let argi=3; process.argv[argi]!= undefined; argi++){
    if (process.argv[argi] == '-w'){
        argi++;
        out_file = process.argv[argi]
    }else{
        signer = process.argv[argi]
    } 
}

a = fs.readFileSync(process.argv[2]);
l = await reader(a);
l.forEach(async (os) => {

    console.log(inspect(os, {
        depth: null,
        customInspect: true,
        maxArrayLength: null,
        showHidden: false
    }));

    if (signer) {
        try {
            a = fs.readFileSync(signer);
            l = await reader(a);
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

    if(out_file){
        try {
            let buf = new ArrayBuffer(2048);
            let dc = new DataCursor(buf);
            os.constructor.to_oer(dc, os);
            fs.writeFileSync(out_file, dc.writen());
        }
        catch (e) {
            console.log("error:" + e.toString());
        }
    }
});
