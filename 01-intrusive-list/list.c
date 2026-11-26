/*
 * Intrusive doubly linked list — the kernel's LIST_ENTRY pattern.
 *
 * Build:  cl list.c   (MSVC)
 *         gcc list.c -o list   (MinGW / GCC)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY;

#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - offsetof(type, field)))

typedef struct _EMPLOYEE {
    int         Id;
    const char *Name;
    LIST_ENTRY  Link;
} EMPLOYEE;

void InitializeListHead(LIST_ENTRY *Head)
{
    Head->Flink = Head;
    Head->Blink = Head;
}

int IsListEmpty(LIST_ENTRY *Head)
{
    return Head->Flink == Head;
}

void InsertTailList(LIST_ENTRY *Head, LIST_ENTRY *Entry)
{
    LIST_ENTRY *OldLast = Head->Blink;

    Entry->Flink    = Head;
    Entry->Blink    = OldLast;
    OldLast->Flink  = Entry;
    Head->Blink     = Entry;
}

void InsertHeadList(LIST_ENTRY *Head, LIST_ENTRY *Entry)
{
    LIST_ENTRY *OldFirst = Head->Flink;

    Entry->Flink     = OldFirst;
    Entry->Blink     = Head;
    OldFirst->Blink  = Entry;
    Head->Flink      = Entry;
}

int RemoveEntryList(LIST_ENTRY *Entry)
{
    LIST_ENTRY *Prev = Entry->Blink;
    LIST_ENTRY *Next = Entry->Flink;

    Prev->Flink = Next;
    Next->Blink = Prev;

    Entry->Flink = NULL;
    Entry->Blink = NULL;

    return Prev == Next;
}

void PrintListForward(LIST_ENTRY *Head)
{
    LIST_ENTRY *Current = Head->Flink;

    printf("  Forward:  ");
    while (Current != Head) {
        EMPLOYEE *Emp = CONTAINING_RECORD(Current, EMPLOYEE, Link);
        printf("[%d %s] -> ", Emp->Id, Emp->Name);
        Current = Current->Flink;
    }
    printf("(head)\n");
}

void PrintListBackward(LIST_ENTRY *Head)
{
    LIST_ENTRY *Current = Head->Blink;

    printf("  Backward: ");
    while (Current != Head) {
        EMPLOYEE *Emp = CONTAINING_RECORD(Current, EMPLOYEE, Link);
        printf("[%d %s] -> ", Emp->Id, Emp->Name);
        Current = Current->Blink;
    }
    printf("(head)\n");
}

int main(void)
{
    LIST_ENTRY Head;
    EMPLOYEE   a = { 1, "Alice", {0} };
    EMPLOYEE   b = { 2, "Bob",   {0} };
    EMPLOYEE   c = { 3, "Carol", {0} };

    InitializeListHead(&Head);
    printf("Empty? %d\n\n", IsListEmpty(&Head));

    InsertTailList(&Head, &a.Link);
    InsertTailList(&Head, &b.Link);
    InsertTailList(&Head, &c.Link);

    printf("After InsertTail(a, b, c):\n");
    PrintListForward(&Head);
    PrintListBackward(&Head);
    printf("  Empty? %d\n\n", IsListEmpty(&Head));

    EMPLOYEE d = { 4, "Dave", {0} };
    InsertHeadList(&Head, &d.Link);

    printf("After InsertHead(d):\n");
    PrintListForward(&Head);
    PrintListBackward(&Head);

    printf("\nRemoving Bob...\n");
    int was_last = RemoveEntryList(&b.Link);
    printf("  List now empty? %d\n", was_last);
    PrintListForward(&Head);

    printf("\nRemoving all...\n");
    RemoveEntryList(&d.Link);
    RemoveEntryList(&a.Link);
    was_last = RemoveEntryList(&c.Link);
    printf("  RemoveEntryList returned: %d  (1 = list is now empty)\n", was_last);
    printf("  Empty? %d\n", IsListEmpty(&Head));

    printf("\n--- CONTAINING_RECORD demo ---\n");
    EMPLOYEE e = { 5, "Eve", {0} };
    InsertTailList(&Head, &e.Link);

    LIST_ENTRY *LinkPtr = Head.Flink;
    EMPLOYEE   *Found   = CONTAINING_RECORD(LinkPtr, EMPLOYEE, Link);

    printf("  Link is at:     %p\n", (void *)LinkPtr);
    printf("  EMPLOYEE is at: %p\n", (void *)Found);
    printf("  Offset of Link in EMPLOYEE: %zu bytes\n", offsetof(EMPLOYEE, Link));
    printf("  Recovered: Id=%d, Name=%s\n", Found->Id, Found->Name);

    return 0;
}
