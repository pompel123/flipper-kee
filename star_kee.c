#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <subghz/subghz_tx.h>
#include <subghz/protocols/keeloq.h>
#include <storage/storage.h>

#define KEYS_FILE_PATH   APP_DATA_PATH("keys.txt")
#define MAX_KEYS 32

typedef struct {
    char name[32];
    uint64_t key;
    uint32_t data;
} KeeLoqEntry;

typedef struct {
    Gui* gui;
    ViewPort* vp;
    FuriMessageQueue* input_queue;
    KeeLoqEntry entries[MAX_KEYS];
    size_t entry_count;
    size_t selected;
} AppContext;

static void render_callback(Canvas* canvas, void* ctx) {
    AppContext* app = ctx;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(app->entry_count == 0) {
        canvas_draw_str(canvas, 10, 30, "Ingen koder funnet!");
        return;
    }

    // Vis navn + index
    for(size_t i = 0; i < app->entry_count; i++) {
        if(i == app->selected) {
            canvas_draw_str(canvas, 5, 15 + i*12, ">");
        }
        canvas_draw_str(canvas, 20, 15 + i*12, app->entries[i].name);
    }
}

static void input_callback(InputEvent* event, void* ctx) {
    AppContext* app = ctx;
    if(event->type == InputTypePress) {
        furi_message_queue_put(app->input_queue, event, 0);
    }
}

static bool load_keys(AppContext* app) {
    Storage* storage = furi_record_open("storage");
    File* file = storage_file_alloc(storage);

    if(!storage_file_open(file, KEYS_FILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FURI_LOG_E("StarKee", "Kunne ikke åpne %s", KEYS_FILE_PATH);
        storage_file_free(file);
        furi_record_close("storage");
        return false;
    }

    char line[128];
    app->entry_count = 0;

    while(app->entry_count < MAX_KEYS && storage_file_gets(file, line, sizeof(line))) {
        if(line[0] == '#' || strlen(line) < 5) continue; // kommentar / tom linje

        KeeLoqEntry* e = &app->entries[app->entry_count];
        uint64_t k = 0;
        uint32_t d = 0;
        if(sscanf(line, "%31[^,],%llx,%x", e->name, &k, &d) == 3) {
            e->key = k;
            e->data = d;
            app->entry_count++;
        }
    }

    storage_file_free(file);
    furi_record_close("storage");
    return app->entry_count > 0;
}

static void send_keeloq(KeeLoqEntry* entry) {
    SubGhzTx* tx = subghz_tx_alloc();
    subghz_tx_set_protocol(tx, &subghz_protocol_keeloq);
    subghz_tx_set_frequency(tx, 433920000);

    uint32_t encrypted = subghz_protocol_keeloq_common_encrypt(entry->data, entry->key);

    SubGhzProtocolEncoder* encoder =
        subghz_protocol_encoder_alloc(&subghz_protocol_keeloq);
    subghz_protocol_encoder_set_data(encoder, &encrypted, sizeof(encrypted));

    FURI_LOG_I("StarKee", "Sender %s (data=0x%08X)", entry->name, entry->data);
    subghz_tx_start(tx, encoder);
    furi_delay_ms(300);
    subghz_tx_stop(tx);

    subghz_protocol_encoder_free(encoder);
    subghz_tx_free(tx);
}

int32_t star_kee_app(void* p) {
    UNUSED(p);

    AppContext app;
    memset(&app, 0, sizeof(app));

    // Init input
    app.input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));

    // Init GUI
    app.vp = view_port_alloc();
    view_port_draw_callback_set(app.vp, render_callback, &app);
    view_port_input_callback_set(app.vp, input_callback, &app);

    app.gui = furi_record_open("gui");
    gui_add_view_port(app.gui, app.vp, GuiLayerFullscreen);

    // Load keys
    if(!load_keys(&app)) {
        FURI_LOG_W("StarKee", "Ingen koder lastet inn");
    }

    // Event loop
    InputEvent event;
    bool running = true;
    while(running) {
        if(furi_message_queue_get(app.input_queue, &event, 100) == FuriStatusOk) {
            if(event.key == InputKeyBack) {
                running = false;
            } else if(event.key == InputKeyUp && app.selected > 0) {
                app.selected--;
            } else if(event.key == InputKeyDown && app.selected + 1 < app.entry_count) {
                app.selected++;
            } else if(event.key == InputKeyOk && app.entry_count > 0) {
                send_keeloq(&app.entries[app.selected]);
            }
            view_port_update(app.vp);
        }
    }

    // Cleanup
    gui_remove_view_port(app.gui, app.vp);
    view_port_free(app.vp);
    furi_message_queue_free(app.input_queue);
    furi_record_close("gui");

    return 0;
}
