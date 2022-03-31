import type {Ieee1609Dot2Certificate, Ieee1609Dot2Data} from "Ieee1609Dot2js";
//import type {EtsiTs102941Data} from "EtsiTs102941js";
declare module 'itsreadjs' {
  export default function ItsSecRead(a: Uint8Array): Promise<(Ieee1609Dot2Certificate|Ieee1609Dot2Data)[]>;
}
