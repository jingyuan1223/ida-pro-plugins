import idaapi
import types
from idautils import *
from idc import *

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"
    

    def init(self):
        return idaapi.PLUGIN_OK 
    
    
    def printflow(self,arg,dictD,idxn,filename):
        if dictD.has_key(arg):
            content=dictD[arg]+" -> "+ idxn+";\n"
        else:
            content="START -> "+idxn+";\n"
        with open(filename, 'a') as file:
            file.write(content)
                   
    def drawDataFlow(self,start,end,dict,dictD,dictR,listPush,filename):
        
        dictR[start]="yes" # record current "start" address has already been searched to prevent self-loop in DFS
        
        for head in Heads(start,end):
            ins_mnem=GetMnem(head)
            if ins_mnem=="mov" or ins_mnem=="lea":
                if GetOpType(head,1)!=5:
                    arg2=GetOpnd(head,1)
                    self.printflow(arg2,dictD,dict[head],filename)
                arg1=GetOpnd(head,0)
                dictD[arg1]=dict[head]
                
            elif ins_mnem =="or" or ins_mnem =="and" or ins_mnem =="xor" or ins_mnem =="sub" or ins_mnem =="add":
                if GetOpType(head,1)!=5:
                    arg2=GetOpnd(head,1)
                    self.printflow(arg2,dictD,dict[head],filename)
                if GetOpnd(head,0)!=GetOpnd(head,1):
                    arg1=GetOpnd(head,0)
                    self.printflow(arg1,dictD,dict[head],filename)
                arg1=GetOpnd(head,0)
                dictD[arg1]=dict[head]
                
            elif ins_mnem=="test" or ins_mnem=="cmp":
                if GetOpType(head,1)!=5:
                    arg2=GetOpnd(head,1)
                    self.printflow(arg2,dictD,dict[head],filename)
                if GetOpType(head,0)!=5 and GetOpnd(head,0)!=GetOpnd(head,1):
                    arg1=GetOpnd(head,0)
                    self.printflow(arg1,dictD,dict[head],filename)
                iarg="eflags"
                dictD[iarg]=dict[head]
                    
            elif ins_mnem == "inc" or ins_mnem =="dec":
                arg=GetOpnd(head,0)
                self.printflow(arg,dictD,dict[head],filename)
                dictD[arg]=dict[head]
                
            elif ins_mnem=="push":
                iarg="esp"
                self.printflow(iarg,dictD,dict[head],filename)
                arg=GetOpnd(head,0)
                self.printflow(arg,dictD,dict[head],filename)
                dictD[iarg]=dict[head]
                listPush.append(dict[head]) # update "shadow stack" 
                
            elif ins_mnem=="pop":
                iarg="esp"
                self.printflow(iarg,dictD,dict[head],filename)
                arg=GetOpnd(head,0)
                if len(listPush)!=0: # use and update "shadow stack"
                    temcontent=listPush.pop()+" -> "+dict[head]+";\n"
                    with open(filename, 'a') as file:
                        file.write(temcontent)
                dictD[iarg]=dict[head]
                dictD[arg]=dict[head]
                
            elif ins_mnem=="call":
                
                # by running idaapi.get_arg_address(), it would return the address of all the arguments in the order they are given when the function is called
                arglist=idaapi.get_arg_addrs(head) 
                
                if arglist:
                    for addr in arglist:
                        if dict.has_key(addr):
                            temcontent=dict[addr]+" -> "+dict[head]+";\n"
                            with open(filename, 'a') as file:
                                file.write(temcontent)
                dictD["eax"]=dict[head]
                        
            elif ins_mnem.startswith('j'):
                temaddr=GetOperandValue(head,0)
                if ins_mnem=="jmp":
                    if dict.has_key(temaddr):
                        
                        temdictD=dictD.copy()
                        temlist=listPush[:]
                        
                        if start!=temaddr and (not dictR.has_key(temaddr)): # check whether the address that the program is going to jump to has been searched before to prevent self-loop
                            self.drawDataFlow(temaddr,end,dict,temdictD,dictR,temlist,filename)
                        return # the control flow has only one way to go, so after jumping to the destination address, this function should return and thus this control flow comes to an end
                else:
                    temcontent=dictD["eflags"]+" -> "+dict[head]+";\n"
                    with open(filename, 'a') as file:
                        file.write(temcontent)
                    
                    # the control flow now has two branches to go
                    # each flow will need current records of defined element and "shadow stack"
                    temdictD2=dictD.copy()
                    temlist2=listPush[:]
                    
                    if start!=temaddr and (not dictR.has_key(temaddr)):# check whether the address that the program is going to jump to has been searched before to prevent self-loop
                        self.drawDataFlow(temaddr,end,dict,temdictD2,dictR,temlist2,filename) # one control flow goes from here
                    # another control flow continues in this drawDataFlow function
            else:
                pass
            

    def run(self, arg):
        print "Plugin Excuted!"
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
                 
                functionName = GetFunctionName(funcea)
                filename="0x%06x"%funcea+".dot"
                
                printcontent = "diagrah" + " " + functionName + " {" + "\n"
                
                dict={} # using this "dict" dictionary to map every instruction address to its index
                num = 0
                
                func=idaapi.get_func(funcea)
                startea=func.startEA
                endea=func.endEA
                
                
                for head in Heads(startea, endea):
                    num += 1
                    insidx="n"+str(num)
                    dict[head]=insidx # map instruction address to its index
                    
                    content =  "n" + str(num) + "      [label =  \""+ "0x%08x"%(head)  + "; " 
                    
                    ins_mnem=GetMnem(head)
                    strD="D: " # record Def
                    strU="U: " # record Use
                    
                    if ins_mnem == "mov" or ins_mnem =="lea" or ins_mnem =="or" or ins_mnem =="and" or ins_mnem =="xor" or ins_mnem =="sub" or ins_mnem =="add":
                        arg1=GetOpnd(head,0)
                        strD += arg1
                        if GetOpType(head,1) != 5:
                            arg2=GetOpnd(head,1)
                            strU += arg2
                    if ins_mnem == "push":
                        strD += "esp" + "[esp]"
                        strU += "esp" + ", "+GetOpnd(head,0)
                    if ins_mnem == "pop":
                        strD += "esp" + ", " + GetOpnd(head,0)
                        strU += "esp" + ", " + "[esp]"
                    if ins_mnem == "test" or ins_mnem =="cmp":
                        strD += "eflags"
                        if GetOpType(head,0) != 5:
                            strU += GetOpnd(head,0)
                        if GetOpType(head,1) != 5:
                            strU += ", " + GetOpnd(head,1)
                    if ins_mnem == "inc" or ins_mnem =="dec":
                        strD += GetOpnd(head,0)
                    if ins_mnem == "call":
                        strD += "eax"
                    if ins_mnem.startswith('j') and ins_mnem != "jmp":
                        strU += "eflags"
                        
                    content += strD + " "+ strU + "\""+"]"+";"+ "\n"
                    printcontent += content
                
                printcontent+="\n"
                
                with open(filename, 'w') as file:
                    file.write(printcontent)
                
                
                # draw data dependency flow
                
                dictD={} # using this dictionary to record which register or element is defined before and where it is defined
                listPush=[] # the "shadow stack" to handle the data dependency problem in push and pop operation
                dictR={} # when using Depth First Search to go through each control flow, this "dictD" records whether one instruction address has been searched before
                
                self.drawDataFlow(startea,endea,dict,dictD,dictR,listPush,filename)
                
                   
                with open(filename, 'a') as file:
                    file.write("\n}")    
        
        print "Plugin End"
            

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()



