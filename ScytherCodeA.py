protocol SmartSociety(User, Cloud, BaseStation){
role User{
const IDu;
const PWu;
const BFu;
fresh Ras;
send_!4(User,Cloud,IDu);
macro BFu=H(BFIu,BFGu); #biometric function
send_!5(User,Cloud,H(IDu, BFIu));
macro BFIu'=H(BFu,BFGu);#biometric ID 
macro Dc'=H(XOR(IDu,PWu),BFIu');
match(Dc', Dc);
macro Ac'=XOR(Bc,H(IDu,H(IDu,BFIu)));
macro Fu=H(IDu,Ac',Ras,T1);
macro Ras-c=XOR (Ras ,H(Ac',T1));
macro Gu=H(IDu,Ac');
send_!6(User,Cloud,Fu,Ras-c,IDu,T1,Gu);
recv_!7(Cloud,User,Hc,Rc-as,IDc,T2);
macro Rc'=ADD(Ras,Ras-c);
macro Hc'=H(IDc,IDu,Ac',BFIu',Rc',T2);
match(Hc', Hc);
macro SKe-v = H(IDc,IDu,Ras,Rc );
claim_User(User,Niagree);
claim_User(User, Nisynch);
claim_User(User,Secret,PWu);
claim_User(User,Secret, SKe-v);
#The Non-injective Synchronization (Ni-Agree) property requires sending and
#receiving events are executed by the runs mentioned by the cast
#function and is implemented in the correct order and with the same contents.
#The Non-injective Agreement (Ni-Agree) has claimed that the sender and 
#the receiver both agree upon the values of the variables that 
#are exchanged in between and the analysis results validate the claim’s correctness.
}

role Cloud{
const Sc;
recv_!1(BaseStation,Cloud,BIDr);
const IDc;
fresh Rc;
macro BSr=H(BIDr,Sc);
send_!2(Cloud,BaseStation,BSr);
recv_!4(User,Cloud,IDu);
recv_!5(User,Cloud,H(IDu, BFIu));
macro Ac=H(H(IDu,BFIu),Sc);
macro Bc=XOR(Ac, H(IDu,H(IDu,BFIu)));
macro Dc=H(XOR(IDu,PWu),BFIu);
macro CBc=H(IDu,BIDr,BSr);
macro Ec=XOR(CBc,H(PWu,BFGu));
recv_!6(User,Cloud,Fu,Ras-c,IDu,T1,Gu);
macro Ac=H(H(IDu,BFIu),Sc);
macro Ras'=XOR(Ras-c, H(Ac,T1));
macro Fu'=H(IDu,Ac,Ras',T1);
match(Fu', Fu);
macro Hc=H(IDc,IDu,Ac,BFIu,Rc,T2);
macro Rc-as=XOR(Ras',Rc);
send_!7(Cloud,User,Hc,Rc-as,IDc,T2);
macro  SKe-v = H(IDc,IDu,Ras,Rc );
claim_Cloud(Cloud,Niagree);
claim_ Cloud (Cloud, Nisynch);
claim_ Cloud (Cloud,Secret, SKe-v);
}}
