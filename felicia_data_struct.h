struct plist{
    unsigned int size;        //子字符串数量
    char **list;            //用字符串数组来存放字符串列表
};

int ListAppend(struct plist *strlist, char *str);
int ListInsert(struct plist *strlist, char* str, unsigned int index);
int ListDeleteLast(struct plist *strlist);
int ListDeleteIndex(struct plist *strlist, unsigned int index);
char* ListGetIndex(struct plist *strlist, unsigned int index);
int ListIn(struct plist *strlist, char* str);
int ListSpaceFree(struct plist *strlist);
void ListShow(struct plist *strlist);