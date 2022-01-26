require 'java'
java_import 'burp.IExtensionHelpers'

java_import 'javax.swing.JOptionPane'
java_import 'burp.ITab'
java_import 'javax.swing.JPanel'
java_import 'javax.swing.JScrollPane'
java_import 'java.awt.Dimension'
java_import 'java.awt.Rectangle'
java_import 'java.awt.event.ComponentListener'

class AbstractBrupExtensionUI < JScrollPane
  include ITab
  include ComponentListener

  def initialize(extension)
    @panel = JPanel.new
    #@panel.setPreferredSize(Dimension.new(1024,768))
    @panel.setLayout nil
    super(@panel)
    @extension = extension
    addComponentListener self
  end

  def extensionName
    @extension.extensionName
  end

  def add(component)
    bounds = component.getBounds
    updateSize(bounds.getX + bounds.getWidth, bounds.getY + bounds.getHeight)
    @panel.add component
  end

  alias_method :getTabCaption, :extensionName

  def getUiComponent
    self
  end

  private
  #Don't set the size smaller than existing widget positions
  def updateSize(x,y)
    x = (@panel.getWidth() > x) ? @panel.getWidth : x
    y = (@panel.getHeight() > y) ? @panel.getHeight : y
    @panel.setPreferredSize(Dimension.new(x,y))
  end

end

java_import('java.awt.Insets')
class AbstractBurpUIElement
  def initialize(parent, obj, positionX, positionY, width, height)
    @swingElement =obj
    setPosition parent, positionX, positionY, width, height
    parent.add @swingElement
  end

  def method_missing(method, *args, &block)
    @swingElement.send(method, *args)
  end

  private
  def setPosition(parent, x,y,width,height)
    insets = parent.getInsets
    size = @swingElement.getPreferredSize()
    w = (width > size.width) ? width : size.width
    h = (height > size.height) ? height : size.height
    @swingElement.setBounds(x + insets.left, y + insets.top, w, h)
  end
end

class BPanel < AbstractBurpUIElement
  include ComponentListener

  def initialize(parent, positionX, positionY, width, height)
    obj = JPanel.new
    obj.setLayout nil
    super parent, obj, positionX,positionY, width, height
  end
end

java_import 'javax.swing.JLabel'
class BLabel < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, align= :left)
    case align
    when :left
      a = 2
    when :right
      a = 4
    when :center
      a = 0
    else
      a = 2 #align left
    end
    super parent, JLabel.new(caption, a),positionX, positionY, width, height
  end
end


java_import 'javax.swing.JButton'
class BButton < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, &onClick)
    super parent, JButton.new(caption), positionX, positionY, width, height
    @swingElement.add_action_listener onClick
  end
end

java_import 'javax.swing.JSeparator'
class BHorizSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

class BVertSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, height)
    super parent, JSeparator.new(1), positionX, positionY, 1, height
  end
end

java_import 'javax.swing.JCheckBox'
class BCheckBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JCheckBox.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JTextField'
class BTextField < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JTextField.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JComboBox'
class BComboBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, &evt)
    super parent, JComboBox.new, positionX, positionY, width, height
    @swingElement.add_action_listener evt
  end
end

java_import 'javax.swing.JTextArea'
class BTextArea < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height)
    @textArea = JTextArea.new
    super parent, JScrollPane.new(@textArea), positionX, positionY, width, height
    @textArea.setLineWrap(true)
  end

  def setText(text)
    @textArea.setText text
  end

  def getText
    @textArea.getText
  end

  def setEditable(value)
    @textArea.setEditable(value)
  end
end

java_import 'burp.ITextEditor'
class BTextEditor < AbstractBurpUIElement
  def initialize(parent, callbacks, positionX, positionY, width, height)
    @textArea = callbacks.createTextEditor
    super parent, JScrollPane.new(@textArea.getComponent), positionX, positionY, width, height
  end

  def setText(text)
    @textArea.setText text.bytes
  end

  def getText
    @textArea.getText.map {|b| b.chr}.join
  end
end

#########################################################################################
#Begin Burp Extension
#########################################################################################

java_import 'burp.IIntruderPayloadProcessor'
require 'base64'
class PayloadProcessorFactory
  SETTINGKEY = 'AdHocExtState'
  attr_reader :extensionName
  attr_accessor :callbacks

  class AbstractPayloadProcessor
    include IIntruderPayloadProcessor

    attr_accessor :originalText

    def initialize(processorName, helpers)
      @processorName = processorName
      @helpers = helpers
    end

    def getProcessorName
      @processorName
    end

    def processPayload(bCurrentPayload, bOriginalPayload, bBaseValue)
      currentPayload = @helpers.bytesToString(bCurrentPayload)
      originalPayload = @helpers.bytesToString(bOriginalPayload)
      baseValue = @helpers.bytesToString(bBaseValue)
      @helpers.stringToBytes(userProcessPayload(currentPayload, originalPayload, baseValue))
    rescue RuntimeError,ArgumentError => e
      puts e.message + ':' + 'for ' + currentPayload + ' / ' + originalPayload + ' / ' + baseValue
      "ERROR"
    end

    def userProcessPayload(currentPayload, originalPayload, baseValue)
      "" #emtpy string
    end

    def method_missing(symbol, *args, &blk)
      if @helpers.respond_to? symbol
        @helpers.send symbol, *args, &blk
      else
        raise NoMethodError.new("Method `#{m}` doesn't exist.")
      end
    end
  end

  def initialize(name)
    @extensionName = name
  end

  def getProcessors
    #Return an array with processor names
    processors = @callbacks.getIntruderPayloadProcessors
    processors.map {|p| p.getProcessorName}
  end

  def getProcessorText(name)
    processors = @callbacks.getIntruderPayloadProcessors
    processors.each {|p| return p.originalText if p.getProcessorName == name}
    ''
  end

  def saveExtensionState
    processors = @callbacks.getIntruderPayloadProcessors
    items = processors.map {|p| [p.getProcessorName, p.originalText]}.to_h
    @callbacks.saveExtensionSetting(SETTINGKEY, Base64.strict_encode64(Marshal.dump(items)))
  end

  def loadExtensionState
    stored = @callbacks.loadExtensionSetting(SETTINGKEY)
    return if stored.nil?
    items = Marshal.load Base64.strict_decode64(stored)
    items.each {|key,value| create(key, value)}
  end

  def destroy(processorName)
    processors = @callbacks.getIntruderPayloadProcessors
    processors.each do |processor|
      if processor.getProcessorName() == processorName
        @callbacks.removeIntruderPayloadProcessor(processor)
        processor = nil
      end
    end
  rescue => e
    raise RuntimeError, "Failed to remove payload Processor: #{e.message}"
  end

  def create(name, body)
    anon = klass(name, body).new(name, @callbacks.getHelpers)
    anon.originalText = body
    callbacks.registerIntruderPayloadProcessor anon
  rescue => e
    raise ScriptError, "Unable to create payload processor #{name}: #{e.message}"
  end

  def test(name, body, currentPayload, originalPayload, baseValue)
    anon = klass(name, body).new(name, @callbacks.getHelpers)
    return anon.userProcessPayload(currentPayload, originalPayload, baseValue)
  end

  def klass(name, body)
    eval "Class.new(AbstractPayloadProcessor) do\n#{body}\nend"
  end
end

class ExtensionUI < AbstractBrupExtensionUI

  SAMPLEBODY = <<"HERE"
#This method is invoked each time the payload processor is applied 
#to an intruder payload.
#
#(string) currentPayload, The value of payload to be processed
#(string) originalPayload, the value of the original payload prior to
#     processing by any already-applied processing rules.
#(string) baseValue the base value of the payload position
# You can also use the string related extension helpers functions 
# urlEncode, urlDecode, base64Encode, base64Encode, stringToBytes, and 
# and bytesToString, directly without additional requires/imports.

def userProcessPayload(currentPayload, originalPayload, baseValue)
  "Sample Payload"
end
HERE

  def buildUI(callbacks)
    @c1 = {}; @c2 = {};
    @c1[:lb1] = BLabel.new self, 2, 2, 300, 0, 'Define Payload Processor:'
    @c2[:lb1] = BLabel.new self, 705, 2, 50, 0, 'Test Processor:'
    @c1[:lb2] = BLabel.new self,2, 26, 0,0,  'Define the body of the ruby function userProcessPayload below.'
    @c1[:lb3] = BLabel.new self, 2,50,0,0, 'The value this function yields will be provided to intruder.'
    @c1[:lb4] = BLabel.new self,2, 74, 0,0,  'You may define additional functions or require external files as well.'
    @c2[:lb2] = BLabel.new self, 705,26,290, 0, "Test the current processor at the left."
    @CtrlPanel = BPanel.new(self, 0,502, 714, 220)
    @txtArea = BTextEditor.new( self, callbacks, 2, 100,700,400)
    @txtArea.setText(SAMPLEBODY)
    @c1[:txtArea] = @txtArea
    BLabel.new @CtrlPanel, 2,0, 0,0, 'Name for payload processor:'
    @txtName = BTextField.new(@CtrlPanel, 362, 0, 350, 12, "NewPayloadProcessor#{rand(5000).to_s}")
    BButton.new( @CtrlPanel, 2, 28, 350,0, 'Create Payload Processor') { |evt| createOnClick }
    @cmbProcs = BComboBox.new(@CtrlPanel, 2, 58, 350, 0) { |evt| onCmbChange }
    @cmbChanges = true
    updateRemoveList
    BButton.new(@CtrlPanel, 362, 58,350,0, 'Remove Processor') {|evt| removeOnClick }
    BButton.new(@CtrlPanel,362,98,350,0, 'Restore Template') {|evt| templateOnClick }
    BButton.new(@CtrlPanel, 2, 98, 350, 0, 'Save Extension State') {|evt| saveOnClick }

    @c2[:lb3] = BLabel.new self, 705,50,290 ,0, "Current Payload Test Value:"
    @txtCurrentValue = BTextField.new(self, 705,74,290,0, "test")
    @c2[:txt1] = @txtCurrentValue
    @c2[:lb4] = BLabel.new self, 705,104,290 ,0, "Original Payload Test Value:"
    @txtOriginalValue = BTextField.new(self, 705,128,290,0, "test")
    @c2[:txt2] = @txtOriginalValue
    @c2[:lb4] = BLabel.new self, 705,156,290 ,0, "Base Test Value:"
    @txtBaseValue = BTextField.new(self, 705,180,290,0, "test")
    @c2[:txt3] = @txtBaseValue
    @c2[:btn1] = BButton.new(self,705,210,290,0, "Execute") { |evt| executeOnClick }
    @c2[:lb5] = BLabel.new self, 705, 240, 290, 0, "Result:"
    @txtResult = BTextArea.new(self, 705, 266,290,78)
    @txtResult.setEditable(false)
    @c2[:txt4] = @txtResult
    componentResized nil
  end

  def componentResized(evt)
    bounds = self.getBounds
    w = bounds.getWidth - 298
    x = bounds.getWidth - 292
    if bounds.getWidth > 1023
      @c1.each_value { |widget| rect = widget.getBounds; h = rect.getHeight; rect.setSize(w,h); widget.setBounds(rect) }
      @c2.each_value { |widget| rect = widget.getBounds; y = rect.getY; rect.setLocation(x,y); widget.setBounds(rect) }
    end
    h = bounds.getHeight
    if h > 619
      rect = @txtArea.getBounds; w = rect.getWidth; rect.setSize(w,h - 226); @txtArea.setBounds(rect)
      h = @txtArea.getBounds().getHeight() + 102
      rect = @CtrlPanel.getBounds
      rect.setLocation(0,h)
      @CtrlPanel.setBounds rect
    end
  end

  def executeOnClick
    @txtResult.setText(@extension.test(@txtName.getText, @txtArea.getText,  @txtCurrentValue.getText, @txtOriginalValue.getText, @txtBaseValue.getText))
  rescue StandardError,ScriptError,SecurityError => e
    JOptionPane.showMessageDialog(self, e.message, 'Error', 0)
  end

  def saveOnClick
    JOptionPane.showMessageDialog(self, "External files and other resources, 'requires' etc are not saved!\nYou will need to ensure these are present for processors that depend on them.")
    @extension.saveExtensionState
  end

  def updateRemoveList
    @cmbChanges = false
    @cmbProcs.removeAllItems
    @extension.getProcessors.each {|p| @cmbProcs.addItem(p) }
    @cmbChanges = true
  end

  def onCmbChange
    if  @cmbChanges == true
      @txtArea.setText(@extension.getProcessorText(@cmbProcs.getSelectedItem))
    end
  end

  def createOnClick
    if @extension.getProcessorText(@txtName.getText) == ''
      @extension.create(@txtName.getText, @txtArea.getText)
      @txtName.setText "NewPayloadProcessor#{rand(5000).to_s}"
    else
      JOptionPane.showMessageDialog(self, 'Name Conflict Please Choose another name.')
    end
    updateRemoveList
  rescue ScriptError => e
    JOptionPane.showMessageDialog(self, e.message, 'Error', 0)
  end

  def templateOnClick
    @txtArea.setText(SAMPLEBODY)
  end

  def removeOnClick
    @extension.destroy(@cmbProcs.getSelectedItem)
    updateRemoveList
  rescue RuntimeError => e
    JOptionPane.showMessageDialog(self, e.message, 'Error', 0)
  end

end


java_import 'burp.IBurpExtender'
class BurpExtender
  include IBurpExtender
  ExtensionName = 'Adhoc Payload Processing'

  def initialize
    @payloadprocessorfactory = PayloadProcessorFactory.new ExtensionName
    @extensionInterface = ExtensionUI.new @payloadprocessorfactory
  end

  def registerExtenderCallbacks(callbacks)
    callbacks.setExtensionName ExtensionName
    callbacks.addSuiteTab @extensionInterface
    @payloadprocessorfactory.callbacks = callbacks
    @payloadprocessorfactory.loadExtensionState
    @extensionInterface.buildUI(callbacks)
  end

end
