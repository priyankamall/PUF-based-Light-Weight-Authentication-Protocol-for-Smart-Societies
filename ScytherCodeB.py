protocol SmartSociety(User, Cloud,BaseStation,SensorNodeAndCamera){
role User{
const IDu;
const PWu;
const BFu;
fresh Ras;
macro CBc'=XOR(Ec,H(PWu',BFGu));
macro Ku=H(IDu,CBc',RANu,T3);
macro RANbs-u=XOR(RANu,H(CBc',T3));
send_!8(User,BaseStation,Ku,RANbs-u,T4,IDu);
recv_!9(BaseStation,User,Lbs,Rbs-u,T5);
macro Rbs'=XOR(RAN,Rbs-u);
macro Lbs^=H(IDu,BIDr,CBc,Rbs');
match(Lbs^,Lbs);
macro SKbs-as= H(IDu,BIDr,Rbs,RANu);
claim_User(User,Niagree);
claim_User(User, Nisynch);
claim_User(User,Secret,PWu);
claim_User(User,Secret,RANbs-u);
claim_User(User,Secret, SKbs-as);

}

role Cloud{
const Sc;
recv_!1(BaseStation,Cloud,BIDr);
const IDc;
fresh Rc;
recv_!10(BaseStation,Cloud,BIDr,Nbc,Obc,Tbc);
macro BSr'=H(BIDr,Sc);
macro Rbc'= XOR(Obc,H(BIDr,BSr',Tbc));
macro Nbc'=H(BIDr,BSr',Rbc');
match(Nbc',Nbc);
fresh Rcb;
macro SKb-c = H(IDc,BIDr,Rbc,Rcb);
macro Rc-b=XOR(Rcb,Rbc);
macro Pcb=H(IDc,BSr,SKb-c,Tcb);
send_!11(Cloud,BaseStation,Tbc,Rc-b,Pcb,IDc);
claim_Cloud(Cloud,Niagree);
claim_ Cloud (Cloud, Nisynch);
claim_Cloud(Cloud,Secret, SKb-c);

}

role BaseStation{
const BIDi;
send_!1(BaseStation,Cloud, BIDr );
recv_!2(Cloud,BaseStation,BSr);
recv_!8(User,BaseStation,Ku,RANbs-u,T4,IDu);
macro CBc=H(IDu,BIDr,BSr);
macro RANu^=XOR(RANbs-u,H(CBc,T3));
macro Ku^=H(IDu,CBc,RANu^,T3);
match(Ku^,Ku);
fresh Rbs;
macro Lbs=H(IDu,BIDr,CBc,Rbs);
send_!9(BaseStation,Lbs,Rbs-u,T5);
fresh Rbc;
macro Nbc=H(BIDr,BSr,Rbc);
macro Obc=XOR(H(BIDr,BSr,Tbc),Rbc);
send_!10(BaseStation,Cloud,BIDr,Nbc,Obc,Tbc);
recv_!11(Cloud,BaseStation,Tbc,Rc-b,Pcb,IDc);
macro Rbc'=XOR(Rc-b,Rbc);
macro Pcb'=H(IDc,BSr,SKb-c,Tcb);
macro SKb-c'=H(IDc,BIDr,Rbc,Rcb);
match(Pcb',Pcb);
send_!12(BaseStation,SensorNodeAndCamera,C1);
recv_!13(SensorNodeAndCamera,BaseStation,ZSs,XSs);
macro SRs^=XOR(R1,ZSs);
macro SKbs-s^=H(R1,SRs^);
macro XSs^=H(SIDp,SRs,R1,SKbs-s^);
match(XSs^,XSs);
claim_BaseStation(BaseStation,Niagree);
claim_BaseStation(BaseStation, Nisynch);
claim_BaseStation(BaseStation,Secret, RANu);
claim_BaseStation(BaseStation,Secret, SKbs-as);

}

role SensorNodeAndCamera{
const SIDp;
const CIDq;
recv_!12(BaseStation,SensorNodeAndCamera,C1);
macro C1=H(R1);
fresh SRs;
macro ZSs=ADD(SRs,R1);
macro SKbs-s=H(R1,SRs);
macro XSs=H(SIDp,SRs,R1,SKbs-s);
send_!13(SensorNodeAndCamera,BaseStation,ZSs,XSs);
claim_SensorNodeAndCamera(SensorNodeAndCamera,Niagree);
claim_SensorNodeAndCamera(SensorNodeAndCamera, Nisynch);

}
}

