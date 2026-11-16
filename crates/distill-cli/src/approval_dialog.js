/* macOS JavaScript for Automation. User data arrives only as JSON on stdin. */
ObjC.import('AppKit');
ObjC.import('Foundation');

function run(argv) {
    var input = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
    var data = JSON.parse(ObjC.unwrap($.NSString.alloc.initWithDataEncoding(input, $.NSUTF8StringEncoding)));
    var app = $.NSApplication.sharedApplication;
    app.setActivationPolicy(1); // Accessory application: no temporary Dock icon.
    app.finishLaunching;
    var alert = $.NSAlert.alloc.init;
    alert.messageText = 'Review a critical command';
    alert.informativeText = 'Distill paused this command. Review what it does before allowing it to run.';
    alert.alertStyle = 2;
    alert.icon = $.NSImage.imageNamed('NSCaution');
    alert.addButtonWithTitle('Block command');
    alert.addButtonWithTitle('Allow once');
    var block = alert.buttons.objectAtIndex(0);
    var allow = alert.buttons.objectAtIndex(1);

    var width = 560;
    var rows = [];
    if (data.explanation) rows.push({title:'AI explanation · GPT-6 Luna', text:data.explanation, height:76});
    if (data.description_unavailable) rows.push({title:'AI explanation unavailable', text:'Review the command and static findings below.', height:32});
    rows.push({title:'Exact command · control characters escaped', text:data.command, height:104, code:true});
    rows.push({title:'Working directory', text:data.cwd, height:36, code:true});
    rows.push({title:'Why Distill paused', text:data.reason || 'Static analysis marked this invocation as critical.', height:64});
    var height = 32 + rows.reduce(function(total, row) { return total + row.height + 38; }, 0);
    var content = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, width, height));
    var y = height;
    rows.forEach(function(row) {
        y -= 18;
        var label = $.NSTextField.alloc.initWithFrame($.NSMakeRect(0, y, width, 18));
        label.stringValue = row.title;
        label.font = $.NSFont.boldSystemFontOfSize(11);
        label.textColor = $.NSColor.secondaryLabelColor;
        label.editable = false;
        label.selectable = false;
        label.bezeled = false;
        label.drawsBackground = false;
        content.addSubview(label);
        y -= row.height + 6;
        var scroll = $.NSScrollView.alloc.initWithFrame($.NSMakeRect(0, y, width, row.height));
        scroll.hasVerticalScroller = true;
        scroll.autohidesScrollers = true;
        scroll.borderType = row.code ? 1 : 0;
        scroll.drawsBackground = row.code === true;
        var text = $.NSTextView.alloc.initWithFrame($.NSMakeRect(0, 0, width - 20, row.height));
        text.editable = false;
        text.selectable = true;
        text.richText = false;
        text.drawsBackground = row.code === true;
        text.textColor = $.NSColor.labelColor;
        text.font = row.code ? $.NSFont.userFixedPitchFontOfSize(12) : $.NSFont.systemFontOfSize(13);
        text.verticallyResizable = true;
        text.horizontallyResizable = false;
        text.autoresizingMask = 2;
        text.textContainer.containerSize = $.NSMakeSize(width - 20, 1000000);
        text.textContainer.widthTracksTextView = true;
        text.string = row.text;
        scroll.documentView = text;
        content.addSubview(scroll);
        y -= 14;
    });
    var footer = $.NSTextField.alloc.initWithFrame($.NSMakeRect(0, 0, width, 28));
    footer.stringValue = 'Your choice applies to this exact invocation only. This request expires in 2 minutes.';
    footer.font = $.NSFont.systemFontOfSize(11);
    footer.textColor = $.NSColor.secondaryLabelColor;
    footer.editable = false;
    footer.bezeled = false;
    footer.drawsBackground = false;
    footer.cell.wraps = true;
    content.addSubview(footer);
    alert.accessoryView = content;
    var window = alert.window;
    alert.layout;
    // Apply after layout: Escape blocks; Allow has no implicit Return shortcut.
    block.keyEquivalent = '\u001b';
    allow.keyEquivalent = '';
    // Read-only native layout probe; never shows a dialog or grants consent.
    if (argv[0] === '--check-layout') return JSON.stringify({
        width:Number(content.frame.size.width), height:Number(content.frame.size.height),
        rows:rows.length, buttons:[ObjC.unwrap(block.title), ObjC.unwrap(allow.title)],
        blockKey:ObjC.unwrap(block.keyEquivalent), allowKey:ObjC.unwrap(allow.keyEquivalent), hasDefault:typeof window.defaultButtonCell.isEqual === 'function'
    });
    window.level = 8;
    window.collectionBehavior = 1 | 256;
    window.hidesOnDeactivate = false;
    window.center;
    app.activateIgnoringOtherApps(true);
    window.makeKeyAndOrderFront(null);
    window.orderFrontRegardless;
    return Number(alert.runModal) === 1001 ? 'DISTILL_APPROVED_ONCE' : 'DISTILL_DENIED';
}
