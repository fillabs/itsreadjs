import { DataCursor } from 'asnjs';
import * as fs from 'fs';
import { HashedId8, Ieee1609Dot2Certificate, Ieee1609Dot2Data } from 'Ieee1609Dot2js';
import { exit } from 'process';
import {inspect} from 'util';
import {ItsSecRead as reader} from './itsread.mjs';

const CreateNewCertificate = "CreateNewCertificate";
const CreateNewMessage     = "CreateNewMessage";

var a, l;
var in_file, out_file, signer;

for(let argi=2; process.argv[argi]!= undefined; argi++){
    if (process.argv[argi] == '-w'){
        argi++;
        out_file = process.argv[argi];
    }else if (process.argv[argi] == '-c'){
        in_file = CreateNewCertificate;
    }else if (process.argv[argi] == '-m'){
        in_file = CreateNewMessage;
    }else if (in_file === undefined) {
        in_file = process.argv[argi];
    }else { 
        signer = process.argv[argi];
    }
}

if(in_file == undefined){
    console.log( process.argv[0] + ' ' + process.argv[1] + ' <in_file|-c|-m> [signer] [-w out_file]');
    exit(1);
}

if(in_file === CreateNewCertificate){
    l = [Ieee1609Dot2Certificate.create()]
}else if (in_file === CreateNewMessage){
    l = [Ieee1609Dot2Data.create()]
}else{
    a = fs.readFileSync(in_file);
    l = await reader(a);
}

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

    if(in_file === CreateNewMessage){
        if (signer) {
            os.content.signedData.signer.certificate = [signer];
        }
    }else if(in_file === CreateNewCertificate){
        if (signer) {
            switch(signer.verificationHashAlgorithm){
                case 'SHA-256':
                case 'SM2':
                    os.issuer.select(0);
                    os.issuer.sha256AndDigest = signer.digest;
                    break;
                case 'SHA-384':
                    os.issuer.select(2);
                    os.issuer.sha384AndDigest = signer.digest;
                    break;
            }
        }
    }else{
        // load
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
        }else if (os.constructor.name === "Ieee1609Dot2Certificate") {
            console.log("Hash   : " + inspect(await os.hash()));
            console.log("Digest : " + inspect(await os.digest()));
        }
            // verify message
      	if(os.signature && signer){
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
        }
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
