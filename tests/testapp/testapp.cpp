#include <iostream>
#include <vector>
#include <cstdint>

class Item {
public:
    uint32_t id;
    std::string name;
};

class Player {
public:
    uint32_t health;
    std::vector<Item> items;

    virtual int print_item_names() {
        for (Item item : items) {
            printf("\tItem name: %s\n", item.name.c_str());
        }

        return 0;
    };
};

int use_player(Player *player) {
    printf("health is %d\n", player->health);
    return player->health + 2;
}

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

//#pragma optimize("", off)
int call_both(int a, int b) {
    int added = add(a, b);
    int subbed = sub(a, b);
    return added + subbed;
}
//#pragma optimize("", on)

//#pragma optimize("", off)
extern "C" int goto_target() {
    return 100;
}
//#pragma optimize("", on)

//#pragma optimize("", off)
int flow_control(int a, int b) {
    // je
    if (a == 20) {
        return add(10, 10);
    }

    // jne
    if (b != 30) {
        return sub(10, 5);
    }

    // je more than 14 bytes after
    if (a == 100) {
        __asm("jmp goto_target");
    }

    // jmp
    if (true) {
        return add(5, 5);
    }
}
//#pragma optimize("", on)

//#pragma optimize("", off)
// e and f should be on the stack
int use_stack(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}
//#pragma optimize("", on)

//#pragma optimize("", off)
int main()
{
    int variable = 2;
    int variable2 = 2;

    Item item;
    item.id = 200;
    item.name = "potion";

    std::vector<Item> items = {item};

    Player player;
    player.health = 100;
    player.items = items;

    printf("locations start\n");
    printf("name:main location:%p\n", main);
    printf("name:add location:%p\n", add);
    printf("name:sub location:%p\n", sub);
    printf("name:call_both location:%p\n", call_both);
    printf("name:flow_control location:%p\n", flow_control);
    printf("name:use_stack location:%p\n", use_stack);
    printf("name:use_player location:%p\n", use_player);
    printf("name:variable location:%p\n", &variable);
    printf("name:variable2 location:%p\n", &variable2);
    printf("name:player location:%p\n", &player);
    printf("locations end\n");

    int count = 0;

    while (true) {
        std::cin.get();

        printf("call loop start #%d\n", count);
        printf("variable is %d\n", variable);
        printf("variable2 is %d\n", variable2);
        printf("add(variable, variable2) = %d\n", add(variable, variable2));
        printf("sub(variable, variable2) = %d\n", sub(variable, variable2));
        printf("call_both(variable, variable2) = %d\n", call_both(variable, variable2));
        printf("flow_control(varable, variable2) = %d\n", flow_control(variable, variable2));
        printf("use_stack(1,2,3,4,5,6) = %d\n", use_stack(1,2,3,4,5,6));
        printf("use_player(&player) = %d\n", use_player(&player));
        printf("player.print_item_names() = %d\n", player.print_item_names());
        printf("call loop end #%d\n", count);

        count += 1;
    }
}
//#pragma optimize("", on)
