import {DataCursor} from "asnjs";

import {Ieee1609Dot2Certificate, Ieee1609Dot2Data} from "Ieee1609Dot2js";

import {EtsiTs102941Data} from "EtsiTs102941js";

import {ScmsPdu} from "Ieee1609Dot2Dot1js";

import {EtsiTs103759Data} from "EtsiTs103759js";

export const ItsSecRead = async function(a) {
    var dc, os, data;
    var ret = [];
    
    dc = new DataCursor(a);
    while (dc.index < dc.byteLength) {
        let type = dc.getUint8(); dc.index--;
        if((type|0x80) === 0x80){
            // Parse Certificate
            os = Ieee1609Dot2Certificate.from_oer(dc);
        } else {
            // Parse Message
            console.log("" + dc.index.toString(16) + ": Data");
            os = Ieee1609Dot2Data.from_oer(dc);
            if (os) {
                if (os.content.signedData) {
                    switch (os.content.signedData.tbsData.headerInfo.psid) {
                        case 624: // ctl
                            let data = os.content.signedData.tbsData.payload.data.content.unsecuredData;
                            dc = new DataCursor(data.buffer, data.byteOffset, data.byteLength);
                            os = EtsiTs102941Data.from_oer(dc);
                    }
                } else if (os.content.encryptedData) {
                    console.log("Encrypted message");
                }
            }
        }
        ret.push(os);
    }
    return ret;
};

export default ItsSecRead;
