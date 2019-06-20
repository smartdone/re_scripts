#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# @Author: smartdone
# @Date:   2019-06-05 18:23

# -*- coding: utf-8 -*-

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from com.pnfsoftware.jeb.client.api import IconType, ButtonGroupType
import os

# hook_template = """
# if(Java.available) {{
#     Java.perform(function(){{
#         var application = Java.use("android.app.Application");
#
#         application.attach.overload('android.content.Context').implementation = function(context) {{
#             var result = this.attach(context); // 先执行原来的attach方法
#             var classloader = context.getClassLoader(); // 获取classloader
#             Java.classFactory.loader = classloader;
#
#             var {simple_class_name} = Java.classFactory.use("{full_class_name}");
#
#             {simple_class_name}.{method_name}.overload({types}).implementation = function({args}) {{
# {log_code}
#             }}
#
#             return result;
#         }}
#     }});
# }}
# """

hook_template = """
if(Java.available) {{
    Java.perform(function(){{

        var {simple_class_name} = Java.use("{full_class_name}");

        {simple_class_name}.{method_name}.overload({types}).implementation = function({args}) {{
{log_code}
        }}

    }});
}}
"""


def generate_type_code(types):
    types = ["'{0}'".format(t) for t in types]
    return ", ".join(types)


def generate_args_code(args):
    return ", ".join(args)


def generate_log_code(types, retval, method_name, class_name, args):
    log_code = ""
    i = 0
    for _type in types:
        log_code += '            console.log("{class_name}->{method_name} (argType: {_type}): " + {arg});\n'.format(
            class_name=class_name, method_name=method_name, _type=_type, arg=args[i])
        i += 1

    if retval != "void":
        log_code += '            var retval = this.{method_name}({args})\n'.format(method_name=method_name,
                                                                                       args=", ".join(args))
        log_code += '            console.log("{class_name}->{method_name} (retType: {_type}): " + retval)\n'.format(
            class_name=class_name, method_name=method_name, _type=retval)
        log_code += '            return retval;\n'
    else:
        log_code += '            this.{method_name}({args});\n'.format(method_name=method_name, args=", ".join(args))

    return log_code


class FridaCodeGenerator(IScript):

    @staticmethod
    def to_canonical_name(dalvik_name):
        dalvik_name = dalvik_name.replace('/', '.')

        type_name = {
            'C': "char",
            'I': "int",
            'B': "byte",
            'Z': "boolean",
            'F': "float",
            'D': "double",
            'S': "short",
            'J': "long",
            'V': "void",
            'L': dalvik_name[1:-1],
            '[': dalvik_name
        }

        return type_name[dalvik_name[0]]

    def run(self, ctx):
        self.keys = {}

        engctx = ctx.getEnginesContext()
        if not engctx:
            print('Back-end engines not initialized')
            return

        projects = engctx.getProjects()
        if not projects:
            print('There is no opened project')
            return

        project = projects[0]  # Get current project(IRuntimeProject)
        print('Decompiling code units of %s...' % project)

        self.dexunit = RuntimeProjectUtil.findUnitsByType(project, IDexUnit, False)[
            0]  # Get dex context, needs >=V2.2.1
        try:
            self.current_unit = ctx.getFocusedView().getActiveFragment().getUnit()  # Get current Source Tab in Focus
            java_class = self.current_unit.getClassElement()  # needs >V2.1.4
            curent_addr = ctx.getFocusedView().getActiveFragment().getActiveAddress()  # needs 2.1.4
            if "(" in curent_addr:
                curent_addr = curent_addr.split("+")[0]
                print("current function: " + curent_addr)
                m = FridaCodeGenerator.get_decompiled_method(self.dexunit, curent_addr)

                method_name = m.getName()
                class_name = FridaCodeGenerator.to_canonical_name(java_class.getName())

                return_type = str(m.getReturnType())

                if method_name == "<clinit>":
                    return

                args = []
                for item in m.getParameters():
                    # print(item.getIdentifier().getName())
                    args.append(str(item.getIdentifier().getName()))

                types = [FridaCodeGenerator.to_canonical_name(param.getType().getSignature()) for param in
                         m.getParameters()]
                if len(args) > 0:
                    if args[0] == "this":
                        args = args[1:]
                        types = types[1:]
                simple_class_name = class_name.split('.')[-1]

                if method_name == "<init>": method_name = "$init"

                type_code = generate_type_code(types)
                args_code = generate_args_code(args)
                log_code = generate_log_code(types, return_type, method_name, simple_class_name,
                                             args)

                hook_code = hook_template.format(simple_class_name=simple_class_name,
                                                 full_class_name=class_name,
                                                 method_name=method_name,
                                                 types=type_code,
                                                 args=args_code,
                                                 log_code=log_code)
                print(hook_code)

                if not isinstance(ctx, IGraphicalClientContext):
                    print('This script must be run within a graphical client')
                    return
                file_name = 'hook_{class_name}.js'.format(class_name=simple_class_name)
                file_path = os.path.join(os.environ['HOME'], file_name)

                value = ctx.displayQuestionBox('Input',
                                               'Enter the hook script save path(Save to directory {file_path} by default)'
                                               .format(file_path=file_path), file_path)
                # print(value)
                # with open(value)
                if value:
                    file_path = value
                try:
                    with open(file_path, "w+") as f:
                        f.write(hook_code)
                        f.flush()
                        ctx.displayMessageBox('Information', 'Frida script save to \n{}'.format(file_path),
                                              IconType.INFORMATION,
                                              ButtonGroupType.OK)
                except Exception as e:
                    print(e)

            else:
                print("Place the cursor in the function you want to generate the Frida code, then run the script")
        except Exception as e:
            print(e)
            print("Place the cursor in the function you want to generate the Frida code, then run the script")

    @staticmethod
    def get_decompiled_method(dex, msig):
        m = dex.getMethod(msig)
        if not m:
            return None

        c = m.getClassType()
        if not c:
            return None

        decompiled = DecompilerHelper.getDecompiler(dex)
        if not decompiled:
            return None

        class_sig = c.getSignature(False)
        java_unit = decompiled.decompile(class_sig)
        if not java_unit:
            return None

        method_sig_0 = m.getSignature(False)
        for m in java_unit.getClassElement().getMethods():
            if m.getSignature() == method_sig_0:
                return m
        return None
