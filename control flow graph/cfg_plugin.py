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

    def run(self, arg):
        print "Plugin Excuted!"
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
                functionName = GetFunctionName(funcea)
                filename=functionName+".dot"
                dict={}
                printcontent = "diagrah" + " " + functionName + " {" + "\n"
                num = 0
                for (startea, endea) in Chunks(funcea):
                    for head in Heads(startea, endea):
                        num += 1
                        insidx="n"+str(num)
                        dict[head]=insidx
                        content =  "n" + str(num) + "      [label =  \""+ "0x%08x"%(head)  + "; " 
                        ins_mnem=GetMnem(head)
                        strD="D: "
                        strU="U: "
                        if ins_mnem == "mov" or ins_mnem =="lea" or ins_mnem =="or" or ins_mnem =="and" or ins_mnem =="xor" or ins_mnem =="sub" or ins_mnem =="add":
                            arg1=GetOpnd(head,0)
                            strD += arg1
                            if GetOpType(head,1) != 5:
                                arg2=GetOpnd(head,1)
                                strU += arg2
                        if ins_mnem == "push":
                            strD += "esp"
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
                        if ins_mnem.startswith('j') and ins_mnem != "jmp":
                            strU += "eflags"
                            
                        content += strD + " "+ strU + "\""+"]"+";"+ "\n"
                        printcontent += content
                       
                    
                    printcontent+="\n"
                    
                    startflag=0
                    lstinsidx=""
                    content=""
                    for head in Heads(startea, endea):
                        if startflag==0:
                            lstinsidx=dict[head]
                            startflag=1
                        else:
                            content += lstinsidx + " -> "
                            lstinsidx = dict[head]
                            content += lstinsidx + "\n"
                             
                            instr_mnem=GetMnem(head)
                            if instr_mnem.startswith('j'):
                                if GetOpType(head,0)==6 or GetOpType(head,0)==7:
                                        temaddr=GetOperandValue(head,0)
                                        
                                        if dict.has_key(temaddr):
                                            content += dict[head] + " -> " + dict[temaddr] + "\n"
                                        if instr_mnem == "jmp":
                                            startflag=0
                    printcontent+=content+"\n}"    
                with open(filename, 'w') as file:
                    file.write(printcontent)    
        
        print "Plugin End"
            

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()



