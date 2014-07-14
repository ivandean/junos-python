'''
Simple XML Parser based on lxml

'''

from lxml import etree

class XMLParser(object):

    root = None

    def __init__(self, xml_data=None, root_tag=None):
        if xml_data is not None:
            parser = etree.XMLParser(remove_blank_text=True)
            self.root = etree.XML(xml_data, parser)
            # self.root = etree.fromstring(xml_data)
        elif root_tag is not None:
            self.root = etree.Element(root_tag)
        else:
            raise Exception('At least one parameter needed')

    def root_tag(self):
        return etree.tostring(self.root.tag)

    def xml_tostring(self, pretty=True):
        return etree.tostring(etree.ElementTree(self.root), pretty_print=pretty,
                            encoding=unicode)

    def get_element(self, path):
        try:
            return self.root.find(path)
        except Exception as e:
            raise e
        
    def get_elements(self, path):
        try:
            return self.root.findall(path)
        except Exception as e:
            raise e

    def get_value(self, path):
        try:
            return self.root.find(path).text
        except Exception as e:
            raise e

    def get_attrib(self, path, attrib_name):
        try:
            return self.root.find(path).attrib['attrib_name']
        except Exception as e:
            raise e

    def set_value(self, path, value):
        try:
            self.root.find(path).text = value
        except Exception as e:
            raise e

    def set_attrib(self, path, attrib_name, attrib_value):
        try:
            self.root.find(path).attrib['attrib_name'] = attrib_value
        except Exception as e:
            raise e

    def generate_new_subelement(self, parent, element_tag, text=None):
        leaf = etree.SubElement(parent, element_tag)
        if text:
            leaf.text = text
        return leaf

    def get_path(self, root, element):
        return etree.ElementTree(root).getpath(element)
    
    def get_root(self):
        return self.root

    def save(self):
        try:
            # return etree.dump(self.root)
            return self.xml_tostring()
        except Exception as e:
            raise e

    def load(self, xml_data):
        self.__init__(xml_data)
